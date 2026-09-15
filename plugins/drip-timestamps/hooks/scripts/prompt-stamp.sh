#!/usr/bin/env bash
# UserPromptSubmit hook — stamps YOUR prompt, both on screen and for the model.
#
# Zero dependencies. Every byte of this payload is built from `date`, so no
# untrusted text ever reaches the JSON and printf can emit it safely. That is
# the whole reason this half needs neither jq nor python3.
#
# Two independent outputs:
#   systemMessage    -> visible to you. Documented as working on all hooks and
#                       all platforms, which is why prompt stamps can render in
#                       surfaces where MessageDisplay may not.
#   additionalContext-> visible to the model, wrapped in <system-reminder>.
#
# Invoked as `bash <this script>` (see hooks.json), so it does not depend on the
# executable bit surviving clones, zips, or Windows checkouts.
set -uo pipefail

# Never break a prompt. Any unexpected failure emits nothing and exits clean;
# Claude Code then proceeds with the prompt untouched.
trap 'exit 0' ERR

if [ "${DRIP_TS_ENABLED:-true}" = "false" ]; then
  exit 0
fi

# Pin a timezone with DRIP_TS_TZ (e.g. "KST", "America/Denver").
# Unset = machine local time.
if [ -n "${DRIP_TS_TZ:-}" ]; then
  . "$(dirname "${BASH_SOURCE[0]}")/lib/resolve-tz.sh"
  TZ="$(resolve_tz "$DRIP_TS_TZ")"
  export TZ
fi

# DRIP_TS_FORMAT is any `date` format string (default %H:%M:%S); %Z is always
# appended so the model keeps the offset regardless of the chosen format.
#
# The `tr -d` strips " and \ from the RESULT. This is the only point where
# non-literal text enters the payload, so sanitizing here is what guarantees
# well-formed JSON without a JSON encoder. Do not remove it.
ts="$(date "+${DRIP_TS_FORMAT:-%H:%M:%S} %Z" | tr -d '"\\')"

if [ -z "$ts" ]; then
  exit 0
fi

out=""

# Visible stamp. Set DRIP_TS_SHOW_PROMPT=false to keep the model-facing half only.
if [ "${DRIP_TS_SHOW_PROMPT:-true}" = "true" ]; then
  out="\"systemMessage\":\"[$ts]\""
fi

# Model-facing context. Set DRIP_TS_INJECT_CONTEXT=false for display-only mode.
if [ "${DRIP_TS_INJECT_CONTEXT:-true}" = "true" ]; then
  if [ -n "$out" ]; then
    out="$out,"
  fi
  out="${out}\"hookSpecificOutput\":{\"hookEventName\":\"UserPromptSubmit\",\"additionalContext\":\"Message sent at local time $ts\"}"
fi

# Both halves disabled: emit nothing rather than an empty object.
if [ -z "$out" ]; then
  exit 0
fi

printf '{%s}\n' "$out"
