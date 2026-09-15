"""Run: python3 test/test_session_title.py

A fake `claude` on PATH stands in for the model, so the suite never makes a
real call. PATH is otherwise /usr/bin:/bin, which keeps any real claude out.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks", "scripts", "session-title.py")

FAKE_CLAUDE = """#!/bin/sh
printf '%s\\n' "$@" > "$FAKE_LOG"
case "$FAKE_MODE" in
  ok) printf '%s' "$FAKE_OUT" ;;
  fail) exit 1 ;;
  slow) sleep 5; printf 'too late' ;;
esac
"""


class SessionTitle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.transcript = os.path.join(self.tmp, "t.jsonl")
        self.log = os.path.join(self.tmp, "claude-args")
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        fake = os.path.join(self.bin, "claude")
        with open(fake, "w") as f:
            f.write(FAKE_CLAUDE)
        os.chmod(fake, 0o755)
        self.cwd = os.path.join(self.tmp, "repo")
        os.mkdir(self.cwd)
        subprocess.run(["git", "init", "-q", "-b", "feat/leads", self.cwd], check=True)

    def run_hook(self, prompt, mode="ok", out="Structured notes display rules", path=None, env=None, stdin=None):
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "cwd": self.cwd,
                   "transcript_path": self.transcript, "session_id": "s1"}
        e = {"PATH": path or f"{self.bin}:/usr/bin:/bin", "FAKE_LOG": self.log,
             "FAKE_MODE": mode, "FAKE_OUT": out, **(env or {})}
        r = subprocess.run([sys.executable, HOOK], input=stdin if stdin is not None else json.dumps(payload),
                           capture_output=True, text=True, env=e)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)["hookSpecificOutput"]["sessionTitle"] if r.stdout.strip() else None

    def claude_was_called(self):
        return os.path.exists(self.log)

    def write_transcript(self, *records):
        # Compact separators, the way Claude Code writes its transcripts.
        with open(self.transcript, "w") as f:
            for r in records:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")

    def test_uses_the_model_title(self):
        self.assertEqual(self.run_hook("Just for this pre-launch phase:\nnotes skip the gate"),
                         "Structured notes display rules")

    def test_the_model_sees_the_whole_prompt_not_just_the_first_line(self):
        self.run_hook("Just for this pre-launch phase:\nnotes skip the gate")
        with open(self.log) as f:
            self.assertIn("notes skip the gate", f.read())

    def test_title_never_carries_the_branch(self):
        self.assertNotIn("feat/leads", self.run_hook("fix the throttle"))

    def test_model_output_is_cleaned(self):
        self.assertEqual(self.run_hook("x", out='"Fix the parser."\nsecond line'), "Fix the parser")

    def test_long_model_output_is_capped(self):
        self.assertEqual(self.run_hook("x", out="y" * 200), "y" * 59 + "…")

    def test_falls_back_to_the_first_line_when_the_model_fails(self):
        self.assertEqual(self.run_hook("fix the throttle\nmore detail", mode="fail"), "fix the throttle")

    def test_falls_back_when_the_model_is_too_slow(self):
        title = self.run_hook("fix the throttle", mode="slow", env={"DRIP_SESSION_TITLE_TIMEOUT": "1"})
        self.assertEqual(title, "fix the throttle")

    def test_uses_the_running_claude_binary_when_none_is_on_path(self):
        # IDE extensions bundle their own CLI and export its path; PATH may have no claude.
        title = self.run_hook("x", path="/usr/bin:/bin",
                              env={"CLAUDE_CODE_EXECPATH": os.path.join(self.bin, "claude")})
        self.assertEqual(title, "Structured notes display rules")

    def test_falls_back_when_claude_is_not_installed(self):
        self.assertEqual(self.run_hook("fix the throttle", path="/usr/bin:/bin"), "fix the throttle")

    def test_fallback_is_capped(self):
        self.assertEqual(self.run_hook("x" * 200, mode="fail"), "x" * 59 + "…")

    def test_existing_title_is_left_alone_without_calling_the_model(self):
        self.write_transcript({"type": "custom-title", "customTitle": "mine"})
        self.assertIsNone(self.run_hook("second prompt"))
        self.assertFalse(self.claude_was_called())

    def test_the_words_custom_title_in_a_message_do_not_count_as_a_title(self):
        self.write_transcript({"type": "user", "message": {"content": '{"type":"custom-title"}'}})
        self.assertEqual(self.run_hook("hello"), "Structured notes display rules")

    def test_the_title_call_itself_is_never_titled(self):
        self.assertIsNone(self.run_hook("hello", env={"DRIP_SESSION_TITLE_CHILD": "1"}))
        self.assertFalse(self.claude_was_called())

    def test_blank_prompt_sets_nothing(self):
        self.assertIsNone(self.run_hook("   \n"))
        self.assertFalse(self.claude_was_called())

    def test_malformed_stdin_is_a_silent_no_op(self):
        self.assertIsNone(self.run_hook("", stdin="not json"))


if __name__ == "__main__":
    unittest.main()
