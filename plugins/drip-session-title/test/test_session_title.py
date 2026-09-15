"""Run: python3 test/test_session_title.py"""
import json
import os
import subprocess
import tempfile
import unittest

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks", "scripts", "session-title.py")


def run(cwd, prompt, transcript):
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "cwd": cwd,
               "transcript_path": transcript, "session_id": "s1"}
    out = subprocess.run(["python3", HOOK], input=json.dumps(payload),
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)["hookSpecificOutput"]["sessionTitle"] if out.strip() else None


class SessionTitle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.transcript = os.path.join(self.tmp, "t.jsonl")

    def repo(self, branch):
        d = os.path.join(self.tmp, "repo")
        os.mkdir(d)
        subprocess.run(["git", "init", "-q", "-b", branch, d], check=True)
        return d

    def write_transcript(self, *records):
        # Compact separators, the way Claude Code writes its transcripts.
        with open(self.transcript, "w") as f:
            for r in records:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")

    def test_branch_and_first_prompt_line(self):
        d = self.repo("feat/leads")
        self.assertEqual(run(d, "fix the throttle\nmore detail", self.transcript),
                         "feat/leads · fix the throttle")

    def test_long_prompt_is_truncated(self):
        d = self.repo("main")
        title = run(d, "x" * 200, self.transcript)
        self.assertEqual(title, "main · " + "x" * 59 + "…")

    def test_folder_name_outside_a_repo(self):
        d = os.path.join(self.tmp, "notes")
        os.mkdir(d)
        self.assertEqual(run(d, "hello", self.transcript), "notes · hello")

    def test_existing_title_is_left_alone(self):
        d = self.repo("main")
        self.write_transcript({"type": "custom-title", "customTitle": "mine"})
        self.assertIsNone(run(d, "second prompt", self.transcript))

    def test_the_words_custom_title_in_a_message_do_not_count_as_a_title(self):
        d = self.repo("main")
        self.write_transcript({"type": "user", "message": {"content": '{"type":"custom-title"}'}})
        self.assertEqual(run(d, "hello", self.transcript), "main · hello")

    def test_blank_prompt_sets_nothing(self):
        d = self.repo("main")
        self.assertIsNone(run(d, "   \n", self.transcript))

    def test_malformed_stdin_is_a_silent_no_op(self):
        r = subprocess.run(["python3", HOOK], input="not json", capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
