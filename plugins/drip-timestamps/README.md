# drip-timestamps

Local time on **both** sides of a Claude Code conversation — your prompts and
Claude's replies — plus the time each prompt was sent, given to the model.

```
[19:15:18] you: fix the parser
[19:15:24] Looking at it now…
```

Forked from [zoharbabin/claude-code-message-timestamps](https://github.com/zoharbabin/claude-code-message-timestamps)
(MIT), with two changes: it stamps your prompts too, and it doesn't need `jq`.

## Install

```bash
claude plugin marketplace add drip-tejas/drip-utils
claude plugin install drip-timestamps@drip-utils
```

Restart Claude Code — plugins load at session start.

## Requirements

Prompt stamps need **nothing**. Reply stamps need `python3` (stdlib only, no
`pip install`), which ships with macOS and effectively every Linux. If it's
missing, reply stamps quietly stop and prompt stamps keep working.

## Configuration

All optional.

| Variable | Default | Effect |
|---|---|---|
| `DRIP_TS_ENABLED` | `true` | `false` turns everything off |
| `DRIP_TS_FORMAT` | `%H:%M:%S` | any `date` format string, e.g. `%I:%M %p` |
| `DRIP_TS_TZ` | unset | pin a zone: `KST`, `PST`, `America/Denver` |
| `DRIP_TS_SHOW_PROMPT` | `true` | visible stamp on your prompts |
| `DRIP_TS_SHOW_ASSISTANT` | `true` | visible stamp on Claude's replies |
| `DRIP_TS_INJECT_CONTEXT` | `true` | tell the model the time |

## How it works

Two hooks that share nothing but a call to `date`, split by dependency so they
fail independently.

**`UserPromptSubmit` → `prompt-stamp.sh`** builds its payload entirely from
`date`, so no untrusted text reaches the JSON and plain `printf` emits it
safely. It returns `systemMessage` (visible to you) and `additionalContext`
(visible to the model, wrapped in `<system-reminder>`).

**`MessageDisplay` → `message-stamp.sh`** fires once per streamed chunk and
stamps only chunk `index == 0`, so the marker appears once per message rather
than before every fragment. This half needs `python3` because `delta` is
arbitrary assistant text and re-emitting it inside JSON requires a real encoder.

Both exit cleanly and emit nothing on any error, so the original text renders
untouched. A timestamp plugin should never be able to eat a message.

## Tests

```bash
bash test/run-tests.sh
```

21 assertions. The one that matters feeds an adversarial delta — quotes,
backslashes, newlines, emoji, shell metacharacters — through the display hook
and asserts it returns byte-identical with only the stamp added.

## License

MIT. Upstream `resolve-tz.sh` retained from zoharbabin's original, also MIT.
