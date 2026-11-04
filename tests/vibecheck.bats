#!/usr/bin/env bats
# Behaviour tests for vibecheck.sh itself (the rule packs are tested separately
# with `semgrep --test --config rules/ tests/ai-fixtures`).
#
# These pin the fail-closed contract: "nothing found" must never be reported for
# "nothing looked". Every test runs only the review pass (or none) against a tiny
# fixture app, so the suite needs bash + jq + git and nothing else - no scanners,
# no network, no API key.
#
#   bats tests/vibecheck.bats
#
# Every `[[ ]]` assertion ends in `|| false`: under bash 3.2 (macOS /bin/bash) a
# failing `[[ ]]` that is not the last line does not fail a bats test.

setup() {
  VC="$BATS_TEST_DIRNAME/../vibecheck.sh"
  APP="$BATS_TEST_TMPDIR/app"
  OUT="$BATS_TEST_TMPDIR/out"
  BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$APP" "$BIN"
  printf 'app.get("/x", (req, res) => res.send(db.find(req.query.id)))\n' > "$APP/server.js"
  unset ANTHROPIC_API_KEY VIBECHECK_REVIEW_CMD
  # Review-only run: every pattern pass skipped explicitly, no PDF, no baseline.
  REVIEW_ONLY=(--dir "$APP" --out "$OUT" --no-baseline --no-pdf
               --skip-secrets --skip-sast --skip-deps --skip-iac)
}

# PATH without any `claude` CLI, so provider detection sees no provider.
path_without_claude() {
  local d out="" IFS=:
  for d in $PATH; do
    [ -x "$d/claude" ] && continue
    out="${out:+$out:}$d"
  done
  printf '%s' "$out"
}

# A fake curl that replays HTTP status codes from $FAKE_CURL_SEQ (comma-separated),
# one per call, writing the matching body to -o and a Retry-After header to -D.
install_fake_curl() {
  cat > "$BIN/curl" <<'SH'
#!/usr/bin/env bash
out=""; hdr=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2;; -D) hdr="$2"; shift 2;; *) shift;; esac
done
n=$(( $(cat "$FAKE_CURL_STATE" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE_CURL_STATE"
code=$(printf '%s' "$FAKE_CURL_SEQ" | cut -d, -f"$n"); code="${code:-200}"
[ -n "$hdr" ] && printf 'HTTP/2 %s\r\nretry-after: 1\r\n\r\n' "$code" > "$hdr"
case "$code" in
  200) body='{"stop_reason":"end_turn","content":[{"type":"text","text":"[]"}]}';;
  401) body='{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}';;
  *)   body='{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}';;
esac
[ -n "$out" ] && printf '%s' "$body" > "$out"
printf '%s' "$code"
SH
  chmod +x "$BIN/curl"
  export FAKE_CURL_STATE="$BATS_TEST_TMPDIR/curl-calls"
}

# ── CLI basics ─────────────────────────────────────────────────────────────

@test "--version prints the script version" {
  run "$VC" --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"$(grep -m1 '^VERSION=' "$VC" | cut -d'"' -f2)"* ]] || false
}

@test "unknown flag is a usage error (exit 2)" {
  run "$VC" --definitely-not-a-flag
  [ "$status" -eq 2 ]
}

# ── coverage guard ─────────────────────────────────────────────────────────

@test "a run where every pass is skipped is ERROR (exit 3), not clean" {
  run "$VC" "${REVIEW_ONLY[@]}" --no-review
  [ "$status" -eq 3 ]
  [[ "$output" == *"no scan pass examined anything"* ]] || false
}

# ── review pass: provider-supplied output ──────────────────────────────────

@test "review: a valid empty array is a clean review (exit 0)" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "[]"'
  [ "$status" -eq 0 ]
  [[ "$output" == *"no findings survived refutation"* ]] || false
}

@test "review: prose with no JSON array fails closed (exit 3)" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "I looked and it seems fine."'
  [ "$status" -eq 3 ]
  [[ "$output" == *"could not parse the review response"* ]] || false
}

# Regression: 0.9.0 turned any bracketed-but-invalid response into [] and
# reported "0 findings" - a review that produced nothing usable read as clean.
@test "review: bracketed prose that is not JSON fails closed (exit 3) - 0.9.0 fail-open" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "The handler at [server.js line 1] looks fine."'
  [ "$status" -eq 3 ]
  [[ "$output" == *"could not parse the review response"* ]] || false
  [[ "$output" != *"no findings survived"* ]] || false
}

@test "review: JSON truncated after an inner bracket fails closed (exit 3) - 0.9.0 fail-open" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'printf "[{\"severity\":\"high\",\"refs\":[1,2],\"title\":\"Any caller"'
  [ "$status" -eq 3 ]
  [[ "$output" == *"could not parse the review response"* ]] || false
}

@test "review: empty provider output fails closed (exit 3)" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'true'
  [ "$status" -eq 3 ]
  [[ "$output" == *"returned nothing"* ]] || false
}

@test "review: a refusal fails closed (exit 3)" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "REFUSAL: cyber"'
  [ "$status" -eq 3 ]
  [[ "$output" == *"declined the review request"* ]] || false
}

# ── review pass: refutation ────────────────────────────────────────────────

finding_cmd() {  # $1 = skeptic verdict
  cat > "$BIN/provider" <<SH
#!/usr/bin/env bash
if grep -q 'You are refuting' ; then echo "$1"; else
  echo '[{"severity":"high","class":"broken-access-control","file":"server.js","line":1,"anchor":"db.find(req.query.id)","title":"Any caller can read any record by id","why":"no ownership check","confidence":"high"}]'
fi
SH
  chmod +x "$BIN/provider"
  printf '%s' "$BIN/provider"
}

@test "review: a finding the skeptics confirm is reported" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd "$(finding_cmd CONFIRMED)"
  [ "$status" -eq 0 ]          # report-only by default
  [ "$(jq '[.active[] | select(.tool=="review")] | length' "$OUT/findings.json")" -eq 1 ]
}

@test "review: a finding the skeptics refute is dropped" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd "$(finding_cmd REFUTED)"
  [ "$status" -eq 0 ]
  [ "$(jq '[.active[] | select(.tool=="review")] | length' "$OUT/findings.json")" -eq 0 ]
  [[ "$output" == *"refuted and dropped"* ]] || false
}

@test "review: --fail-on-review lets a surviving high finding gate (exit 1)" {
  run "$VC" "${REVIEW_ONLY[@]}" --review --fail-on-review --review-cmd "$(finding_cmd CONFIRMED)"
  [ "$status" -eq 1 ]
}

# ── review pass: provider detection ────────────────────────────────────────

@test "review: explicit --review with no provider is ERROR (exit 3)" {
  PATH="$(path_without_claude)" run "$VC" "${REVIEW_ONLY[@]}" --review
  [ "$status" -eq 3 ]
  [[ "$output" == *"no provider available"* ]] || false
}

@test "review: default-on review with no provider skips, it does not error" {
  PATH="$(path_without_claude)" run "$VC" "${REVIEW_ONLY[@]}"
  [[ "$output" == *"no model provider"* ]] || false
  [[ "$output" != *"review: --review requested"* ]] || false
}

# ── review pass: HTTP API error handling (fake curl) ───────────────────────

@test "api: a 401 fails closed and names the API error" {
  install_fake_curl
  FAKE_CURL_SEQ=401 ANTHROPIC_API_KEY=test PATH="$BIN:$(path_without_claude)" \
    run "$VC" "${REVIEW_ONLY[@]}" --review
  [ "$status" -eq 3 ]
  [[ "$output" == *"HTTP 401"* ]] || false
  [[ "$output" == *"authentication_error"* ]] || false
  [ "$(cat "$FAKE_CURL_STATE")" -eq 1 ]     # not retried
}

@test "api: a transient 529 is retried and the review completes" {
  install_fake_curl
  FAKE_CURL_SEQ=529,200 ANTHROPIC_API_KEY=test VIBECHECK_REVIEW_RETRIES=3 \
    PATH="$BIN:$(path_without_claude)" run "$VC" "${REVIEW_ONLY[@]}" --review
  [ "$status" -eq 0 ]
  [[ "$output" == *"no findings survived refutation"* ]] || false
  [ "$(cat "$FAKE_CURL_STATE")" -eq 2 ]
}

@test "api: retries are bounded and then fail closed" {
  install_fake_curl
  FAKE_CURL_SEQ=529,529,529 ANTHROPIC_API_KEY=test VIBECHECK_REVIEW_RETRIES=2 \
    PATH="$BIN:$(path_without_claude)" run "$VC" "${REVIEW_ONLY[@]}" --review
  [ "$status" -eq 3 ]
  [[ "$output" == *"HTTP 529"* ]] || false
  [ "$(cat "$FAKE_CURL_STATE")" -eq 2 ]
}
