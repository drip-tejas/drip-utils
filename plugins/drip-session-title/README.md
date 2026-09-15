# drip-session-title

Claude Code titles every session automatically. This plugin writes the title
itself: on your first prompt it asks Haiku, with instructions you can read in
the script, for a few words naming what the session is about.

```
can you check why pnpm test is red on the leads route    ->  Debug leads route test failure
the agent that renames sessions needs a wack on the heda  ->  Session renaming agent needs fixing
```

## Install

```bash
claude plugin marketplace add drip-tejas/drip-utils
claude plugin install drip-session-title@drip-utils
```

Restart Claude Code. Plugins load at session start.

## Requirements

`python3` (stdlib only) and a logged-in Claude Code. The title call uses the
CLI your session is running from (`CLAUDE_CODE_EXECPATH`), or `claude` on your
PATH.

## Behavior

- The title is set once, on your first prompt. Later prompts don't change it.
- Your first prompt waits for the title, usually 5 to 8 seconds. If Haiku
  fails or hasn't answered within 10 seconds, the first line of the prompt
  becomes the title instead.
- If the session already has a custom title, from `/rename` or from this hook
  on an earlier prompt, the hook leaves it alone and makes no call. A name you
  pick always wins.
- Titles are cut at 60 characters.
- Resuming an older session that only has an auto-generated title gives it a
  new title on your next prompt. In VS Code, a tab that is already open may
  keep its old name until you reopen the session.
- On any error the hook prints nothing and exits 0, so your prompt goes through
  untouched.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `DRIP_SESSION_TITLE_TIMEOUT` | `10` | seconds to wait for Haiku before falling back to the first line |

## How it works

A `UserPromptSubmit` hook runs `claude -p` on Haiku with its own short system
prompt, no tools, no MCP servers, no settings and no saved session. It runs
from the temp directory so your project's CLAUDE.md stays out of the call, and
it sets `DRIP_SESSION_TITLE_CHILD=1` so the call can't trigger the hook again.

The hook returns the result as `hookSpecificOutput.sessionTitle`. Claude Code
stores that as a `custom-title` record, the same as `/rename`, and its own
titler skips a session that already has one.

Each new session costs one small Haiku request on your account.

`sessionTitle` isn't in the hooks documentation yet. It was verified on Claude
Code 2.1.232 and 2.1.268; older versions may not support it.

## Tests

```bash
python3 test/test_session_title.py
```

A fake `claude` stands in for the model, so the suite makes no real calls.

## License

MIT. See the repository [LICENSE](../../LICENSE).
