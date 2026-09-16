#!/usr/bin/env bash
# MessageDisplay hook: prepends [HH:MM:SS] to each assistant message on screen.
#
# Display-only: MessageDisplay never changes the stored transcript or what the
# model sees, so the marker cannot confuse Claude.
#
# MessageDisplay fires once per streamed batch with a zero-based `index`. We
# stamp only index 0, so the marker appears once per message rather than before
# every chunk.
#
# Why python3 and not bash: `delta` is arbitrary assistant text: quotes,
# backslashes, newlines, emoji, half-open code fences. Re-emitting that inside
# JSON requires a real encoder. Hand-rolled bash escaping corrupts output, and
# corrupting the assistant's message is far worse than showing no timestamp.
# python3's `json` is stdlib, so this needs no pip install.
#
# Invoked as `bash <this script>` (see hooks.json), so it does not depend on the
# executable bit.
set -uo pipefail

# Fail safe, three ways. Emitting nothing makes Claude Code display the original
# text unchanged. Never swallow assistant output.
command -v python3 >/dev/null 2>&1 || exit 0

if [ "${DRIP_TS_ENABLED:-true}" = "false" ]; then
  exit 0
fi
if [ "${DRIP_TS_SHOW_ASSISTANT:-true}" = "false" ]; then
  exit 0
fi

# Pin a timezone with DRIP_TS_TZ (e.g. "KST", "America/Denver").
if [ -n "${DRIP_TS_TZ:-}" ]; then
  . "$(dirname "${BASH_SOURCE[0]}")/lib/resolve-tz.sh"
  TZ="$(resolve_tz "$DRIP_TS_TZ")"
  export TZ
fi

# No %Z here: the on-screen marker stays short. The model-facing half
# (prompt-stamp.sh) is what carries the timezone.
#
# Computed with `date`, not python/jq time helpers, so it honours TZ and local
# DST the same way the prompt stamp does.
ts="$(date "+${DRIP_TS_FORMAT:-%H:%M:%S}")" || exit 0

DRIP_TS_STAMP="$ts" python3 -c '
import json, os, sys

# Build the whole payload before writing a single byte. A partial write would
# be malformed JSON; an empty write is a clean no-op that Claude Code handles.
try:
    data = json.load(sys.stdin)
    delta = data.get("delta", "")
    if data.get("index") == 0:
        delta = "[" + os.environ["DRIP_TS_STAMP"] + "] " + delta
    out = json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "MessageDisplay",
            "displayContent": delta,
        }
    })
except Exception:
    sys.exit(0)

sys.stdout.write(out + "\n")
' || exit 0
