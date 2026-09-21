# drip-session-title

Claude Code titles every session automatically. This plugin writes the title
itself: it asks Haiku, with instructions you can read in the script, for a few
words naming what the session is about.

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

- **No prompt ever waits for the model.** Your first prompt starts the title
  call in the background and goes straight through. A prompt or two later, once
  the answer has landed, the title appears.
- A long session is renamed **once**, at 25 prompts by default, from what it
  has recently been about rather than its opening line. A session that starts
  on one thing and spends hours on another ends up named for the latter. There
  is never a third name.
- A short session is named once and never renamed.
- `/rename` always wins. Once the hook sees a title it did not write, it stops
  touching that session for good.
- If Haiku fails, or `claude` isn't found, **nothing is set.** The session keeps
  Claude Code's own name. It will never title a session with a truncated slab
  of your own prompt.
- Titles are cut at 60 characters.
- On any error the hook prints nothing and exits 0, so your prompt goes through
  untouched.

## Configuration

All optional.

| Variable | Default | Effect |
|---|---|---|
| `DRIP_SESSION_TITLE_RENAME_AT` | `25` | prompts before the one rename; set very high to never rename |
| `DRIP_SESSION_TITLE_STATE` | `~/.claude/drip-session-title` | where per-session state is kept |

## How it works

A `UserPromptSubmit` hook spawns `claude -p` on Haiku detached, with its own
short system prompt, no tools, no MCP servers, no settings and no saved
session. It sets `DRIP_SESSION_TITLE_CHILD=1` so the call can't trigger the
hook again. The hook does not wait for it: the call writes its answer to a
file, and a later prompt reads that file and returns the title as
`hookSpecificOutput.sessionTitle`. Claude Code stores that as a `custom-title`
record, the same as `/rename`.

That answer file is written under a temporary name and renamed into place, so
a prompt can never read a half-written title.

Whether a session has already been named is kept in this plugin's own state
directory, keyed by session id. It is deliberately **not** read back out of
Claude Code's transcript. That file gets rewritten while the session runs, and
a read landing mid-rewrite looks exactly like "never titled", which is what
used to make a session rename itself after a follow-up prompt. The transcript
is still read for one purpose: spotting a title the hook did not write, which
means you ran `/rename`.

The prompt sent to Haiku is trimmed to 600 characters. Latency scales with
input, and sending up to 4000 made the call take 18 seconds.

Each session costs one small Haiku request, or two if it runs long enough to be
renamed.

`sessionTitle` isn't in the hooks documentation yet. It was verified on Claude
Code 2.1.232, 2.1.268 and 2.1.274; older versions may not support it.

## Tests

```bash
python3 test/test_session_title.py
```

A fake `claude` stands in for the model, so the suite makes no real calls.

## License

MIT. See the repository [LICENSE](../../LICENSE).
