"""Run: python3 test/test_session_title.py

A fake `claude` on PATH stands in for the model, so the suite never makes a
real call. PATH is otherwise /usr/bin:/bin, which keeps any real claude out.

The hook never waits for the model. It spawns the call detached on one prompt
and emits the answer on a later one, so most tests here drive several prompts
and assert on what each one emits.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks", "scripts", "session-title.py")

FAKE_CLAUDE = """#!/bin/sh
printf '%s\\n' "$@" >> "$FAKE_LOG"
case "$FAKE_MODE" in
  ok) printf '%s' "$FAKE_OUT" ;;
  fail) exit 1 ;;
  slow) sleep 5; printf '%s' "$FAKE_OUT" ;;
esac
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.transcript = os.path.join(self.tmp, "t.jsonl")
        self.log = os.path.join(self.tmp, "claude-args")
        self.state = os.path.join(self.tmp, "state")
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        fake = os.path.join(self.bin, "claude")
        with open(fake, "w") as f:
            f.write(FAKE_CLAUDE)
        os.chmod(fake, 0o755)
        self.cwd = os.path.join(self.tmp, "repo")
        os.mkdir(self.cwd)
        subprocess.run(["git", "init", "-q", "-b", "feat/leads", self.cwd], check=True)

    def run_hook(self, prompt, mode="ok", out="Structured notes display rules",
                 path=None, env=None, stdin=None, session="s1"):
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "cwd": self.cwd,
                   "transcript_path": self.transcript, "session_id": session}
        e = {"PATH": path or f"{self.bin}:/usr/bin:/bin", "FAKE_LOG": self.log,
             "FAKE_MODE": mode, "FAKE_OUT": out,
             "DRIP_SESSION_TITLE_STATE": self.state, **(env or {})}
        r = subprocess.run([sys.executable, HOOK],
                           input=stdin if stdin is not None else json.dumps(payload),
                           capture_output=True, text=True, env=e)
        self.assertEqual(r.returncode, 0, r.stderr)
        if not r.stdout.strip():
            return None
        return json.loads(r.stdout)["hookSpecificOutput"]["sessionTitle"]

    def title_within(self, tries=8, **kw):
        """Drive prompts until one emits a title. Returns (title, prompts_taken)."""
        for i in range(1, tries + 1):
            t = self.run_hook(f"follow up {i}", **kw)
            if t:
                return t, i
            time.sleep(0.25)
        return None, tries

    def claude_was_called(self):
        return os.path.exists(self.log)

    def model_args(self):
        with open(self.log) as f:
            return f.read()

    def write_transcript(self, *records):
        # Compact separators, the way Claude Code writes its transcripts.
        with open(self.transcript, "w") as f:
            for r in records:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")


class Naming(Base):
    def test_the_first_prompt_emits_nothing(self):
        self.assertIsNone(self.run_hook("why is pnpm test red on the leads route"))

    def test_the_first_prompt_starts_the_model_in_the_background(self):
        self.run_hook("why is pnpm test red on the leads route")
        for _ in range(20):
            if self.claude_was_called():
                break
            time.sleep(0.25)
        self.assertTrue(self.claude_was_called())

    def test_a_later_prompt_emits_the_model_title(self):
        self.run_hook("why is pnpm test red on the leads route")
        title, _ = self.title_within()
        self.assertEqual(title, "Structured notes display rules")

    def test_the_title_is_emitted_only_once(self):
        self.run_hook("first")
        title, _ = self.title_within()
        self.assertIsNotNone(title)
        for i in range(4):
            self.assertIsNone(self.run_hook(f"later {i}"))

    def test_the_model_sees_the_whole_prompt_not_just_the_first_line(self):
        self.run_hook("Just for this pre-launch phase:\nnotes skip the gate")
        self.title_within()
        self.assertIn("notes skip the gate", self.model_args())

    def test_title_never_carries_the_branch(self):
        self.run_hook("fix the throttle")
        title, _ = self.title_within()
        self.assertNotIn("feat/leads", title)

    def test_model_output_is_cleaned(self):
        self.run_hook("x", out='"Fix the parser."\nsecond line')
        title, _ = self.title_within(out='"Fix the parser."\nsecond line')
        self.assertEqual(title, "Fix the parser")

    def test_long_model_output_is_capped(self):
        self.run_hook("x", out="y" * 200)
        title, _ = self.title_within(out="y" * 200)
        self.assertEqual(title, "y" * 59 + "…")


class NeverBlocks(Base):
    def test_a_slow_model_does_not_delay_the_prompt(self):
        start = time.time()
        self.run_hook("fix the throttle", mode="slow")
        self.assertLess(time.time() - start, 2.5)

    def test_a_slow_model_still_names_the_session_eventually(self):
        self.run_hook("fix the throttle", mode="slow")
        time.sleep(6)
        title, _ = self.title_within(mode="slow")
        self.assertEqual(title, "Structured notes display rules")

    def test_the_prompt_sent_to_the_model_is_trimmed(self):
        self.run_hook("x" * 5000)
        self.title_within()
        self.assertLess(len(self.model_args()), 2000)


class NoUglyTitles(Base):
    def test_a_failed_model_call_never_emits_the_raw_prompt(self):
        self.run_hook("You are writing the weekly work-journal summary for 2026-W38", mode="fail")
        title, _ = self.title_within(mode="fail")
        self.assertIsNone(title)

    def test_a_missing_claude_never_emits_the_raw_prompt(self):
        self.run_hook("Audit contact surfaces across the site", path="/usr/bin:/bin")
        title, _ = self.title_within(path="/usr/bin:/bin")
        self.assertIsNone(title)


class ManualRenameWins(Base):
    def test_a_title_we_did_not_write_stops_it_permanently(self):
        self.write_transcript({"type": "custom-title", "customTitle": "mine"})
        self.assertIsNone(self.run_hook("second prompt"))
        self.assertFalse(self.claude_was_called())

    def test_a_rename_after_we_named_it_is_not_overwritten(self):
        self.run_hook("first")
        title, _ = self.title_within()
        self.assertIsNotNone(title)
        self.write_transcript({"type": "custom-title", "customTitle": "renamed by hand"})
        for i in range(40):
            self.assertIsNone(self.run_hook(f"later {i}", out="Something else entirely"))

    def test_the_words_custom_title_in_a_message_do_not_count_as_a_title(self):
        self.write_transcript({"type": "user", "message": {"content": '{"type":"custom-title"}'}})
        self.run_hook("hello")
        title, _ = self.title_within()
        self.assertEqual(title, "Structured notes display rules")

    def test_a_torn_transcript_read_never_causes_a_rename(self):
        # Claude Code rewrites this file under us; a read that misses the marker
        # must not be read as "never titled". RENAME_AT is pinned out of reach so
        # that the only thing this can catch is the torn read.
        env = {"DRIP_SESSION_TITLE_RENAME_AT": "999"}
        self.run_hook("first", env=env)
        title, _ = self.title_within(env=env)
        self.assertIsNotNone(title)
        open(self.transcript, "w").close()  # the torn read: file momentarily empty
        for i in range(30):
            self.assertIsNone(self.run_hook(f"later {i}", out="Wrong new name", env=env))


class SecondNaming(Base):
    def name_it(self):
        self.run_hook("first", out="First name")
        title, used = self.title_within(out="First name")
        self.assertEqual(title, "First name")
        return used + 1

    def test_a_long_session_is_renamed_once_at_the_threshold(self):
        turns = self.name_it()
        env = {"DRIP_SESSION_TITLE_RENAME_AT": "12"}
        seen = None
        for i in range(turns, 40):
            t = self.run_hook(f"turn {i}", out="Second name", env=env)
            if t:
                seen = t
                break
            time.sleep(0.15)
        self.assertEqual(seen, "Second name")

    def test_a_short_session_is_never_renamed(self):
        turns = self.name_it()
        env = {"DRIP_SESSION_TITLE_RENAME_AT": "99"}
        for i in range(turns, 30):
            self.assertIsNone(self.run_hook(f"turn {i}", out="Second name", env=env))

    def test_there_is_no_third_naming(self):
        turns = self.name_it()
        env = {"DRIP_SESSION_TITLE_RENAME_AT": "12"}
        count = 0
        for i in range(turns, 60):
            if self.run_hook(f"turn {i}", out="Second name", env=env):
                count += 1
            time.sleep(0.1)
        self.assertEqual(count, 1)


class Safety(Base):
    def test_the_title_call_itself_is_never_titled(self):
        self.assertIsNone(self.run_hook("hello", env={"DRIP_SESSION_TITLE_CHILD": "1"}))
        self.assertFalse(self.claude_was_called())

    def test_blank_prompt_sets_nothing(self):
        self.assertIsNone(self.run_hook("   \n"))
        self.assertFalse(self.claude_was_called())

    def test_malformed_stdin_is_a_silent_no_op(self):
        self.assertIsNone(self.run_hook("", stdin="not json"))

    def test_two_sessions_do_not_share_a_title(self):
        self.run_hook("first", session="a", out="Session A")
        for i in range(8):
            if self.run_hook(f"more {i}", session="a", out="Session A"):
                break
            time.sleep(0.25)
        self.assertIsNone(self.run_hook("first", session="b", out="Session B"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
