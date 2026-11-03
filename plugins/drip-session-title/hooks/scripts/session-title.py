#!/usr/bin/env python3
"""UserPromptSubmit hook: name the session after what it is about.

The hook never waits for the model. One prompt spawns a detached Haiku call
that writes its answer to a file; a later prompt finds that answer and emits
it as the session title. So the model's latency (6 to 18 seconds, scaling
with prompt length) costs the prompt nothing, and there is no timeout to
fall back from.

A long session is renamed once, around DRIP_SESSION_TITLE_RENAME_AT prompts,
from its recent prompts rather than its opening line. Never a third time.

Whether this session has been titled is recorded in our own state directory,
keyed by session id. It is NOT read back out of Claude Code's transcript:
that file is rewritten under us, and a read landing mid-rewrite used to look
like "never titled" and rename the session after a follow-up prompt. The
transcript is still read for one thing only, a title we did not write, which
means /rename and stops us permanently.

Tests: python3 test/test_session_title.py
"""
import json
import os
import re
import subprocess
import sys

MAX_TITLE = 60
MAX_PROMPT_CHARS = 600  # latency scales with this; 4000 chars made an 18s call
KEEP_PROMPTS = 6
RENAME_AT = 25

SYSTEM = ("You name Claude Code sessions. Reply with only a title of 3 to 6 words "
          "naming the task or topic of the message you are given. Sentence case. "
          "No quotes, no trailing punctuation.")

# Runs detached. Writes to a temp path and renames, so the answer file is never
# visible half-written to the next prompt's read.
SPAWN = '''
out=$("$1" -p "$3" --model haiku --no-session-persistence --setting-sources "" \
      --strict-mcp-config --tools "" --system-prompt "$4" < /dev/null 2>/dev/null) || exit 0
[ -n "$out" ] || exit 0
printf '%s' "$out" > "$2.part" && mv "$2.part" "$2"
'''


def state_dir():
    d = os.environ.get("DRIP_SESSION_TITLE_STATE") or os.path.expanduser("~/.claude/drip-session-title")
    os.makedirs(d, exist_ok=True)
    return d


def safe_name(session_id):
    return "".join(c for c in session_id if c.isalnum() or c in "-_")[:64] or "unknown"


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save(path, state):
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, path)


LEADING_BLOCK = re.compile(r"\s*<([A-Za-z][\w.-]*)\b[^>]*>.*?</\1>", re.S)


def skip_leading_blocks(prompt):
    """Drop tagged blocks the IDE puts ahead of what the user typed.

    A <browser_instruction> block alone is longer than MAX_PROMPT_CHARS, so
    left in it is all the model sees. A prompt that is nothing but blocks is
    kept as is, so there is still something to title.
    """
    rest = prompt
    while True:
        m = LEADING_BLOCK.match(rest)
        if not m:
            break
        rest = rest[m.end():]
    return rest.strip() or prompt


def clean(text):
    line = next((l.strip() for l in text.splitlines() if l.strip()), "")
    line = line.strip("\"'*` ").rstrip(".!?:;").strip()
    return line if len(line) <= MAX_TITLE else line[: MAX_TITLE - 1] + "…"


def read_answer(path):
    try:
        with open(path, encoding="utf-8") as f:
            return clean(f.read())
    except OSError:
        return ""


def spawn(message, answer_path):
    # IDE extensions bundle their own CLI and export its path, so prefer that over PATH.
    exe = os.environ.get("CLAUDE_CODE_EXECPATH")
    if not exe:
        from shutil import which
        exe = which("claude")
    if not exe:
        return False
    try:
        subprocess.Popen(
            ["sh", "-c", SPAWN, "_", exe, answer_path, message[:MAX_PROMPT_CHARS], SYSTEM],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,  # outlives this hook; nothing waits on it
            cwd=os.path.dirname(answer_path),  # keeps the project's CLAUDE.md out of the call
            env={**os.environ, "DRIP_SESSION_TITLE_CHILD": "1"},  # the call must not title itself
        )
    except OSError:
        return False
    return True


def foreign_title(transcript, ours):
    """True when the transcript holds a title we did not write, i.e. a /rename.

    A torn or missing read answers False. Our own state already decides whether
    to title, so missing this check costs a check, never an unwanted rename.
    """
    try:
        with open(transcript, encoding="utf-8", errors="ignore") as f:
            body = f.read()
    except OSError:
        return False
    found = None
    for line in body.splitlines():
        if '"type":"custom-title"' not in line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue  # a half-written last line
        if rec.get("type") == "custom-title" and rec.get("customTitle"):
            found = rec["customTitle"]
    return bool(found) and found not in ours


def emit(title):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "sessionTitle": title,
    }}))


def collect(answer, st, path, next_stage):
    """Emit the background answer if it has landed, else wait for a later prompt."""
    title = read_answer(answer)
    if title:
        st["stage"] = next_stage
        st["titles"] = st["titles"] + [title]
    save(path, st)
    if title:
        emit(title)


def main():
    if os.environ.get("DRIP_SESSION_TITLE_CHILD"):
        return
    data = json.load(sys.stdin)
    prompt = skip_leading_blocks((data.get("prompt") or "").strip())
    if not prompt:
        return

    d = state_dir()
    sid = safe_name(data.get("session_id") or "")
    path = os.path.join(d, sid + ".json")
    st = load(path)
    if st.get("stage") == "done":
        return

    if foreign_title(data.get("transcript_path") or "", st.get("titles") or []):
        st["stage"] = "done"
        save(path, st)
        return

    st["turns"] = st.get("turns", 0) + 1
    st["prompts"] = (st.get("prompts") or [])[-(KEEP_PROMPTS - 1):] + [prompt[:MAX_PROMPT_CHARS]]
    st.setdefault("titles", [])
    stage = st.get("stage") or "new"
    rename_at = int(os.environ.get("DRIP_SESSION_TITLE_RENAME_AT") or RENAME_AT)

    # Stage 1 names the session from its opening prompt; stage 2 renames a long
    # session from what it has actually been about. Each spawns on one prompt
    # and emits on a later one, so no prompt ever waits for the model.
    if stage == "new":
        st["stage"] = "naming" if spawn(prompt, os.path.join(d, sid + ".a1")) else "done"
        save(path, st)
    elif stage == "naming":
        collect(os.path.join(d, sid + ".a1"), st, path, "named")
    elif stage == "named" and st["turns"] >= rename_at:
        st["stage"] = "renaming" if spawn("\n".join(st["prompts"]), os.path.join(d, sid + ".a2")) else "done"
        save(path, st)
    elif stage == "renaming":
        collect(os.path.join(d, sid + ".a2"), st, path, "done")
    else:
        save(path, st)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # a title is never worth blocking a prompt
