# drip-timestamps: design

**Date:** 2026-08-09
**Status:** approved, implemented
**Origin:** fork of [zoharbabin/claude-code-message-timestamps](https://github.com/zoharbabin/claude-code-message-timestamps) (MIT), audited and installed before forking.

## Purpose

Show local time on both sides of a Claude Code conversation, and tell the model
when each prompt was sent.

Two changes from the upstream plugin:

1. **Stamp the user's prompts, not just Claude's replies.** Upstream only stamps
   assistant messages, so a transcript shows when answers arrived but never when
   questions were asked.
2. **Drop the `jq` dependency.** Upstream hard-requires `jq` and silently
   disables itself without it.

## Architecture

The two halves share nothing but a call to `date`. They are split by
**dependency**, not by feature. That split is what lets the zero-dependency
half keep working when the other cannot run.

| Hook | Script | Dependency | Output field | Reach |
|---|---|---|---|---|
| `UserPromptSubmit` | `prompt-stamp.sh` | none | `systemMessage` + `additionalContext` | all platforms |
| `MessageDisplay` | `message-stamp.sh` | `python3` (stdlib only) | `displayContent` | terminal confirmed; webview unverified |

### Why the prompt half needs no JSON tool

Its payload is built entirely from `date` output. No untrusted text reaches the
JSON, so `printf` emits it safely. The single exception is `DRIP_TS_FORMAT`,
whose formatted result is interpolated into the payload, and `tr -d '"\\'` strips
the only two characters that could produce malformed JSON. That sanitizer is
load-bearing and has a dedicated test.

### Why the assistant half does

`delta` is arbitrary streamed assistant text: quotes, backslashes, newlines,
emoji, half-open code fences. Re-emitting it inside JSON needs a real encoder.
Hand-rolled bash escaping would corrupt assistant output, which is a far worse
failure than showing no timestamp. `python3`'s `json` module is stdlib, so this
costs no install.

### Why `systemMessage` for prompt stamps

`MessageDisplay` is documented in the Claude Code binary as firing "while an
**assistant** message streams". It never fires for user messages, so it cannot
stamp prompts. `systemMessage` is documented as "Display a message to the user
(all hooks)", making it the only available mechanism, and the one most likely to
render outside the terminal.

## Error handling

Both scripts exit 0 with empty stdout on any failure. Claude Code then renders
the original text untouched. A timestamp plugin must never be able to break a
prompt or swallow a message. `message-stamp.sh` builds its entire payload
before writing a byte, so a mid-serialization error cannot emit partial JSON.

Fail-safe paths covered: missing `python3`, malformed stdin, hostile format
string, `date` failure.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `DRIP_TS_ENABLED` | `true` | `false` disables both halves |
| `DRIP_TS_FORMAT` | `%H:%M:%S` | any `date` format string |
| `DRIP_TS_TZ` | unset | pin a zone; accepts abbreviations (`KST`) or IANA names |
| `DRIP_TS_SHOW_PROMPT` | `true` | visible stamp on your prompts |
| `DRIP_TS_SHOW_ASSISTANT` | `true` | visible stamp on Claude's replies |
| `DRIP_TS_INJECT_CONTEXT` | `true` | model-facing time context |

## Deliberate omissions

**The `SessionStart` dependency-check hook.** Upstream needs it because without
`jq` it degrades to completely silent. Ours cannot: the pure-bash half keeps
stamping prompts regardless, so a missing `python3` presents as "reply stamps
stopped, prompt stamps didn't", so the plugin diagnoses itself. A hook that
restates what the behavior already shows is not worth its file.

**Elapsed time and response duration.** Considered and cut as out of scope.
`MessageDisplay` fires per chunk with no completion event, so duration would
need session-JSONL parsing, a different and much larger design.

## Testing

`test/run-tests.sh`, assert-based, no framework. 21 cases.

The case that justifies the whole design is **round-trip**: an adversarial
delta containing quotes, backslashes, newlines, tabs, emoji, angle brackets,
shell metacharacters and a literal `%` must come back byte-identical with only
the stamp prefixed. If that passes, the `python3` dependency is earning its
keep. Verified passing.

## Known unknown

`systemMessage`'s schema example reads `"Warning shown to user in UI"`. Whether
the VS Code webview styles it as a warning banner (visually loud on every
prompt) is unverified until a session restart. If it renders badly, the
fallback is `DRIP_TS_SHOW_PROMPT=false`, keeping the model-facing half. That
would mean visible prompt stamps are not achievable through the hook system at
all, which is worth knowing before any further polish.

Likewise `MessageDisplay` rendering in the webview is unproven; plugins load at
session start, so neither could be tested in the session that built this.
