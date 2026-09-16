#!/usr/bin/env python3
"""UserPromptSubmit hook: name the session after what your first prompt is about.

Asks Haiku for a 3 to 6 word title. If that fails, or takes longer than
DRIP_SESSION_TITLE_TIMEOUT seconds (default 10), the first line of the prompt
is used instead. An existing custom title is never overridden, so a /rename
always wins.
Tests: python3 test/test_session_title.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile

MAX_TITLE = 60
MAX_PROMPT_CHARS = 4000
SYSTEM = ("You name Claude Code sessions. Reply with only a title of 3 to 6 words "
          "naming the task or topic of the message you are given. Sentence case. "
          "No quotes, no trailing punctuation.")


def cap(title):
    return title if len(title) <= MAX_TITLE else title[: MAX_TITLE - 1] + "…"


def ask_model(prompt):
    # IDE extensions bundle their own CLI and export its path, so prefer that over PATH.
    exe = os.environ.get("CLAUDE_CODE_EXECPATH") or shutil.which("claude")
    if not exe:
        return ""
    message = f"Title this message:\n<message>\n{prompt[:MAX_PROMPT_CHARS]}\n</message>"
    cmd = [exe, "-p", message, "--model", "haiku", "--no-session-persistence",
           "--setting-sources", "", "--strict-mcp-config", "--tools", "",
           "--system-prompt", SYSTEM]
    try:
        p = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True,
            cwd=tempfile.gettempdir(),  # keeps the project's CLAUDE.md and memory out of the call
            env={**os.environ, "DRIP_SESSION_TITLE_CHILD": "1"},  # the call must not title itself
        )
    except OSError:
        return ""
    try:
        out, _ = p.communicate(timeout=float(os.environ.get("DRIP_SESSION_TITLE_TIMEOUT") or 10))
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)  # the whole group, so nothing holds the pipe open
        return ""
    if p.returncode != 0:
        return ""
    line = next((l.strip() for l in out.splitlines() if l.strip()), "")
    return line.strip("\"'*` ").rstrip(".!?:;").strip()


def main():
    if os.environ.get("DRIP_SESSION_TITLE_CHILD"):
        return
    data = json.load(sys.stdin)
    transcript = data.get("transcript_path") or ""
    # A title record is a top-level "type":"custom-title". Inside message text the
    # quotes arrive JSON-escaped, so a raw '"custom-title"' only matches the record.
    # ponytail: scans the whole transcript each prompt; fine until transcripts hit hundreds of MB
    if os.path.exists(transcript):
        with open(transcript, encoding="utf-8", errors="ignore") as f:
            if '"custom-title"' in f.read():
                return

    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return
    first_line = next(l.strip() for l in prompt.splitlines() if l.strip())
    title = ask_model(prompt) or first_line

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "sessionTitle": cap(title),
    }}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # a title is never worth blocking a prompt
