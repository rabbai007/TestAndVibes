#!/usr/bin/env bash
# Detection benchmark: did VibeCheck find the vulnerabilities it must find?
#
#   tests/benchmark/check.sh <findings.json> [expected.json] [pass,pass,...]
#
# Every finding counts (active, accepted by a baseline, or out of a --diff
# scope): the question is detection, not gating. The optional third argument
# limits the checks to those passes (e.g. "sast,secrets" for a source-only run).
# Exits 1 if any expected detection is missing, 2 on bad input.
set -uo pipefail
F="${1:?usage: check.sh findings.json [expected.json] [passes]}"
E="${2:-$(dirname "$0")/expected.json}"
ONLY="${3:-}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
jq -e '.active | type == "array"' "$F" >/dev/null 2>&1 || { echo "not a VibeCheck findings.json: $F" >&2; exit 2; }

miss=0; hit=0
printf '%-20s %-8s %5s  %s\n' CHECK PASS FOUND "EXPECTED DETECTION"
while IFS=$'\t' read -r id pass sel why; do
  if [ -n "$ONLY" ] && ! printf ',%s,' "$ONLY" | grep -q ",$pass,"; then continue; fi
  n="$(jq "[(.active + (.accepted // []) + (.out_of_scope // []))[] | select($sel)] | length" "$F" 2>/dev/null)"
  if [ -z "$n" ]; then echo "bad selector in check $id" >&2; exit 2; fi
  if [ "$n" -gt 0 ]; then hit=$((hit+1)); mark="ok"; else miss=$((miss+1)); mark="MISSING"; fi
  printf '%-20s %-8s %5s  %-7s %s\n' "$id" "$pass" "$n" "$mark" "$why"
done < <(jq -r '.checks[] | [.id, .pass, .select, .why] | @tsv' "$E")

# A pass that did not complete makes every check on it meaningless.
errs="$(jq -r '.coverage.passes[] | select(.status == "error") | "\(.pass): \(.detail)"' "$F")"
printf '\n%d of %d expected detections found\n' "$hit" "$((hit + miss))"
[ -n "$errs" ] && printf '\nFAIL: passes that did not complete (their checks mean nothing):\n%s\n' "$errs"
[ "$miss" -eq 0 ] && [ -z "$errs" ]
