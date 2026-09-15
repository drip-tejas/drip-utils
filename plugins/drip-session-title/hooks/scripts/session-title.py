#!/usr/bin/env python3
"""UserPromptSubmit hook: title the session "<branch> · <first prompt line>".

Sets the title once. Any existing custom title (this hook's or a /rename)
is left alone, so it never fights a name you chose.
Tests: python3 test/test_session_title.py
"""
import json
import os
import subprocess
import sys

MAX_PROMPT = 60


def main():
    data = json.load(sys.stdin)
    transcript = data.get("transcript_path") or ""
    # A title record is a top-level "type":"custom-title". Inside message text the
    # quotes arrive JSON-escaped, so a raw '"custom-title"' only matches the record.
    # ponytail: scans the whole transcript each prompt; fine until transcripts hit hundreds of MB
    if os.path.exists(transcript):
        with open(transcript, encoding="utf-8", errors="ignore") as f:
            if '"custom-title"' in f.read():
                return

    line = next((l.strip() for l in (data.get("prompt") or "").splitlines() if l.strip()), "")
    if not line:
        return
    if len(line) > MAX_PROMPT:
        line = line[: MAX_PROMPT - 1] + "…"

    cwd = data.get("cwd") or os.getcwd()
    branch = subprocess.run(["git", "-C", cwd, "branch", "--show-current"],
                            capture_output=True, text=True).stdout.strip()
    where = branch or os.path.basename(os.path.normpath(cwd))

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "sessionTitle": f"{where} · {line}",
    }}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # a title is never worth blocking a prompt
