#!/usr/bin/env bash
# One runnable check. No framework, no fixtures — just asserts.
#
# The test that earns its keep is ROUND-TRIP: feed message-stamp.sh a delta full
# of quotes, backslashes, newlines and emoji, and prove the text comes back
# byte-identical with only the stamp added. That single case is the entire
# justification for taking a python3 dependency instead of escaping in bash.
#
# Run: bash test/run-tests.sh
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROMPT="$DIR/hooks/scripts/prompt-stamp.sh"
MESSAGE="$DIR/hooks/scripts/message-stamp.sh"

pass=0
fail=0

ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL %s\n     %s\n' "$1" "$2"; }

# Every hook must emit either valid JSON or nothing at all. Never anything else.
assert_json_or_empty() {
  local label="$1" out="$2"
  if [ -z "$out" ]; then
    ok "$label (empty, valid no-op)"
    return
  fi
  if printf '%s' "$out" | python3 -m json.tool >/dev/null 2>&1; then
    ok "$label"
  else
    bad "$label" "not valid JSON: $out"
  fi
}

assert_contains() {
  local label="$1" hay="$2" needle="$3"
  case "$hay" in
    *"$needle"*) ok "$label" ;;
    *)           bad "$label" "expected to find [$needle] in: $hay" ;;
  esac
}

assert_empty() {
  local label="$1" out="$2"
  if [ -z "$out" ]; then ok "$label"; else bad "$label" "expected empty, got: $out"; fi
}

echo
echo "prompt-stamp.sh (zero-dependency half)"

out="$(printf '{}' | bash "$PROMPT")"
assert_json_or_empty "emits valid JSON" "$out"
assert_contains "carries a visible systemMessage" "$out" '"systemMessage"'
assert_contains "carries model-facing context" "$out" '"additionalContext"'

out="$(printf '{}' | DRIP_TS_TZ=KST DRIP_TS_FORMAT='%I:%M %p' bash "$PROMPT")"
assert_json_or_empty "TZ + format override still valid JSON" "$out"
assert_contains "honours TZ override (KST)" "$out" 'KST'

out="$(printf '{}' | DRIP_TS_INJECT_CONTEXT=false bash "$PROMPT")"
assert_json_or_empty "context opt-out still valid JSON" "$out"
case "$out" in
  *additionalContext*) bad "INJECT_CONTEXT=false drops model context" "still present: $out" ;;
  *)                   ok "INJECT_CONTEXT=false drops model context" ;;
esac

out="$(printf '{}' | DRIP_TS_SHOW_PROMPT=false bash "$PROMPT")"
case "$out" in
  *systemMessage*) bad "SHOW_PROMPT=false drops visible stamp" "still present: $out" ;;
  *)               ok "SHOW_PROMPT=false drops visible stamp" ;;
esac

assert_empty "both halves off emits nothing" \
  "$(printf '{}' | DRIP_TS_SHOW_PROMPT=false DRIP_TS_INJECT_CONTEXT=false bash "$PROMPT")"

assert_empty "DRIP_TS_ENABLED=false disables entirely" \
  "$(printf '{}' | DRIP_TS_ENABLED=false bash "$PROMPT")"

# A format string containing a double quote must not produce malformed JSON.
# This is the sanitizer's reason to exist.
out="$(printf '{}' | DRIP_TS_FORMAT='%H:%M"broken\\' bash "$PROMPT")"
assert_json_or_empty "hostile format string cannot break JSON" "$out"

echo
echo "message-stamp.sh (python3 half)"

out="$(printf '{"index":0,"delta":"Hello."}' | bash "$MESSAGE")"
assert_json_or_empty "emits valid JSON" "$out"
assert_contains "stamps the first chunk" "$out" '] Hello.'

out="$(printf '{"index":1,"delta":" continued"}' | bash "$MESSAGE")"
assert_json_or_empty "later chunk still valid JSON" "$out"
assert_contains "passes later chunks through unstamped" "$out" '" continued"'
case "$out" in
  *'] '*) bad "later chunk is not stamped" "found a stamp in: $out" ;;
  *)      ok "later chunk is not stamped" ;;
esac

# THE test. Adversarial delta -> displayContent must equal it byte for byte,
# with only the stamp prefixed. Compared in python so we diff real strings
# rather than shell-mangled ones.
NASTY='He said "hi" \ backslash
newline	tab 🎉 emoji <tag> ${notavar} `cmd` '"'"'quote'"'"' 100%'

export NASTY
payload="$(python3 -c 'import json,os,sys; sys.stdout.write(json.dumps({"index":0,"delta":os.environ["NASTY"]}))')"
out="$(printf '%s' "$payload" | bash "$MESSAGE")"
assert_json_or_empty "adversarial delta emits valid JSON" "$out"

export ROUNDTRIP_OUT="$out"
if python3 -c '
import json, os, re, sys
raw = os.environ["ROUNDTRIP_OUT"]
original = os.environ["NASTY"]
shown = json.loads(raw)["hookSpecificOutput"]["displayContent"]
stripped = re.sub(r"^\[[^\]]*\] ", "", shown, count=1)
sys.exit(0 if stripped == original else 1)
'; then
  ok "adversarial delta round-trips byte-identical"
else
  bad "adversarial delta round-trips byte-identical" "text was mangled"
fi

# Missing python3 must degrade silently, not error or emit junk.
assert_empty "no python3 on PATH degrades to a clean no-op" \
  "$(printf '{"index":0,"delta":"x"}' | PATH=/nonexistent bash "$MESSAGE" 2>/dev/null)"

assert_empty "DRIP_TS_SHOW_ASSISTANT=false disables stamping" \
  "$(printf '{"index":0,"delta":"x"}' | DRIP_TS_SHOW_ASSISTANT=false bash "$MESSAGE")"

# Malformed input from a future schema change must not produce garbage.
assert_empty "malformed stdin degrades to a clean no-op" \
  "$(printf 'not json at all' | bash "$MESSAGE" 2>/dev/null)"

echo
printf '%d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
