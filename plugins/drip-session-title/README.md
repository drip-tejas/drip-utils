# drip-session-title

Claude Code gives every session a title written by a small model. This plugin
replaces it with something predictable: the git branch and the first line of
your first prompt.

```
phase-22-c-offering-detail-redesign · fix the gate card spacing
main · review PR 190
notes · draft the launch email        (outside a git repo, the folder name)
```

## Install

```bash
claude plugin marketplace add drip-tejas/drip-utils
claude plugin install drip-session-title@drip-utils
```

Restart Claude Code. Plugins load at session start.

## Requirements

`python3` (stdlib only). `git` is optional: without a repo, the folder name
stands in for the branch.

## Behavior

- The title is set once, on the first prompt. Later prompts don't change it.
- If the session already has a custom title, from `/rename` or from this hook
  on an earlier prompt, the hook leaves it alone. A name you pick always wins.
- The prompt part is cut at 60 characters.
- Resuming an older session that only has an auto-generated title gives it a
  new title on your next prompt.
- On any error the hook prints nothing and exits 0, so your prompt goes through
  untouched.

## How it works

A `UserPromptSubmit` hook returns `hookSpecificOutput.sessionTitle`. Claude Code
stores that the way it stores a `/rename`: as a `custom-title` record in the
session transcript. Before setting a title, the hook looks for an existing
`custom-title` record in the transcript and stops if it finds one.

`sessionTitle` isn't in the hooks documentation yet. It was verified on Claude
Code 2.1.232; older versions may not support it.

## Tests

```bash
python3 test/test_session_title.py
```

## License

MIT. See the repository [LICENSE](../../LICENSE).
