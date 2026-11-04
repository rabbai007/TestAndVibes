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

# One sanitised PATH for the whole file: every executable on the real PATH except
# model providers and scanners, so a test sees exactly the tools it installs as
# fakes in $BIN - never whatever happens to be on the developer's machine.
setup_file() {
  local clean="$BATS_FILE_TMPDIR/clean-bin" d f n IFS=:
  mkdir -p "$clean"
  for d in $PATH; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
      n="${f##*/}"
      case "$n" in claude|ant|trivy|osv-scanner|grype|npm|semgrep|trufflehog|gitleaks) continue;; esac
      [ -x "$f" ] && [ ! -e "$clean/$n" ] && ln -s "$f" "$clean/$n"
    done
  done
  export CLEAN_PATH="$clean"
}

# PATH with no model provider (and no scanners).
path_without_claude() { printf '%s' "$CLEAN_PATH"; }

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

@test "--help executes nothing (regression: a backtick in the help heredoc ran an external program)" {
  printf '#!/bin/sh\ntouch "%s/claude-ran"\n' "$BATS_TEST_TMPDIR" > "$BIN/claude"; chmod +x "$BIN/claude"
  PATH="$BIN:$CLEAN_PATH" run "$VC" --help
  [ "$status" -eq 0 ]
  [ ! -e "$BATS_TEST_TMPDIR/claude-ran" ]
  [[ "$output" == *'the `claude` CLI'* ]] || false
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

# ── CISA KEV (fake trivy / grype / curl; KEV catalog from a local fixture) ─

# A python app with two dependency CVEs, both rated MEDIUM by the "scanner":
# CVE-2099-0001 is in the KEV fixture, CVE-2099-0002 is not.
kev_setup() {
  printf 'demo==1.0\nother==2.0\n' > "$APP/requirements.txt"
  cat > "$BATS_TEST_TMPDIR/trivy.json" <<'JSON'
{"Results":[{"Target":"requirements.txt","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2099-0001","PkgName":"demo","InstalledVersion":"1.0","Severity":"MEDIUM","Title":"demo is exploitable"},
 {"VulnerabilityID":"CVE-2099-0002","PkgName":"other","InstalledVersion":"2.0","Severity":"MEDIUM","Title":"other has a bug"}]}]}
JSON
  cat > "$BATS_TEST_TMPDIR/kev.json" <<'JSON'
{"catalogVersion":"2099.01.01","dateReleased":"2099-01-01T00:00:00Z","count":2,"vulnerabilities":[
 {"cveID":"CVE-2099-0001","vendorProject":"Demo","product":"demo","vulnerabilityName":"Demo RCE",
  "dateAdded":"2099-01-01","dueDate":"2099-01-22","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2099-9999","vendorProject":"X","product":"x","vulnerabilityName":"X",
  "dateAdded":"2099-01-01","dueDate":"2099-01-22","knownRansomwareCampaignUse":"Unknown"}]}
JSON
  export FAKE_TRIVY_JSON="$BATS_TEST_TMPDIR/trivy.json"
  cat > "$BIN/trivy" <<'SH'
#!/usr/bin/env bash
case " $* " in *" --version "*) echo "Version: 0.0.0-fake"; exit 0;; esac
out=""; while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done
cp "$FAKE_TRIVY_JSON" "$out"
SH
  chmod +x "$BIN/trivy"
  DEPS_ONLY=(--dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review
             --skip-secrets --skip-sast --skip-iac)
}
kev_run() { PATH="$BIN:$CLEAN_PATH" run "$VC" "$@"; }

@test "kev: a KEV-listed medium CVE is raised to critical and gates (exit 1)" {
  kev_setup
  kev_run "${DEPS_ONLY[@]}" --kev-file "$BATS_TEST_TMPDIR/kev.json"
  [ "$status" -eq 1 ]
  [[ "$output" == *"actively exploited"* ]] || false
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .severity' "$OUT/findings.json")" = critical ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .severity_original' "$OUT/findings.json")" = medium ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .kev.ransomware' "$OUT/findings.json")" = Known ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0002") | .severity' "$OUT/findings.json")" = medium ]
}

@test "kev: without KEV the same scan passes the high gate (the gap KEV closes)" {
  kev_setup
  kev_run "${DEPS_ONLY[@]}" --no-kev
  [ "$status" -eq 0 ]
  [ "$(jq '[.active[] | select(.kev != null)] | length' "$OUT/findings.json")" -eq 0 ]
}

@test "kev: no KEV match leaves severities alone and records an ok check" {
  kev_setup
  jq '.vulnerabilities |= map(select(.cveID != "CVE-2099-0001"))' "$BATS_TEST_TMPDIR/kev.json" > "$BATS_TEST_TMPDIR/kev2.json"
  kev_run "${DEPS_ONLY[@]}" --kev-file "$BATS_TEST_TMPDIR/kev2.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"none of 2 dependency CVE(s) are known-exploited"* ]] || false
}

@test "kev: a GHSA finding matches KEV through grype's CVE alias" {
  kev_setup
  printf '{"Results":[{"Target":"requirements.txt","Vulnerabilities":[]}]}' > "$FAKE_TRIVY_JSON"
  cat > "$BIN/grype" <<'SH'
#!/usr/bin/env bash
[ "$1" = version ] && { echo "Version: 0.0.0-fake"; exit 0; }
out=""; while [ $# -gt 0 ]; do [ "$1" = "--file" ] && out="$2"; shift; done
cat > "$out" <<'JSON'
{"matches":[{"vulnerability":{"id":"GHSA-aaaa-bbbb-cccc","severity":"Medium","dataSource":""},
  "relatedVulnerabilities":[{"id":"CVE-2099-0001"}],
  "artifact":{"name":"demo","version":"1.0"}}]}
JSON
SH
  chmod +x "$BIN/grype"
  kev_run "${DEPS_ONLY[@]}" --kev-file "$BATS_TEST_TMPDIR/kev.json"
  [ "$status" -eq 1 ]
  [ "$(jq -r '.active[] | select(.rule=="GHSA-aaaa-bbbb-cccc") | .kev.cve' "$OUT/findings.json")" = CVE-2099-0001 ]
}

@test "kev: --kev-file that does not exist fails closed (exit 3)" {
  kev_setup
  kev_run "${DEPS_ONLY[@]}" --kev-file "$BATS_TEST_TMPDIR/nope.json"
  [ "$status" -eq 3 ]
  [[ "$output" == *"KEV file not found"* ]] || false
}

@test "kev: a catalog with no vulnerabilities array fails closed (exit 3)" {
  kev_setup
  printf '{"catalogVersion":"x","vulnerabilities":[]}' > "$BATS_TEST_TMPDIR/empty.json"
  kev_run "${DEPS_ONLY[@]}" --kev-file "$BATS_TEST_TMPDIR/empty.json"
  [ "$status" -eq 3 ]
  [[ "$output" == *"not a valid catalog"* ]] || false
}

@test "kev: default-on with the feed unreachable warns and records 'NOT checked' (no exit 3)" {
  kev_setup; install_fake_curl
  FAKE_CURL_SEQ=000 kev_run "${DEPS_ONLY[@]}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"CISA KEV NOT checked"* ]] || false
  [ "$(jq -r '.coverage.passes[] | select(.pass=="kev") | .status' "$OUT/findings.json")" = skipped ]
}

@test "kev: explicit --kev with the feed unreachable fails closed (exit 3)" {
  kev_setup; install_fake_curl
  FAKE_CURL_SEQ=503 kev_run "${DEPS_ONLY[@]}" --kev
  [ "$status" -eq 3 ]
  [[ "$output" == *"HTTP 503"* ]] || false
}

@test "kev: a baseline entry accepted before KEV listing is re-gated; one accepted as KEV is not" {
  kev_setup
  BL="$BATS_TEST_TMPDIR/baseline.json"
  DEPS_BL=(--dir "$APP" --out "$OUT" --no-pdf --no-review --skip-secrets --skip-sast --skip-iac --baseline "$BL")
  # accept everything while CISA had not listed it
  kev_run "${DEPS_BL[@]}" --no-kev --write-baseline
  [ "$status" -eq 0 ]
  [ "$(jq '[.entries[] | select(.kev == true)] | length' "$BL")" -eq 0 ]
  # now it is KEV-listed: the old acceptance must not hold
  kev_run "${DEPS_BL[@]}" --kev-file "$BATS_TEST_TMPDIR/kev.json"
  [ "$status" -eq 1 ]
  [[ "$output" == *"accepted before CVE-2099-0001 was listed in CISA KEV"* ]] || false
  # a deliberate re-acceptance with KEV known records kev:true and suppresses it
  kev_run "${DEPS_BL[@]}" --kev-file "$BATS_TEST_TMPDIR/kev.json" --write-baseline
  [ "$(jq '[.entries[] | select(.kev == true)] | length' "$BL")" -eq 1 ]
  kev_run "${DEPS_BL[@]}" --kev-file "$BATS_TEST_TMPDIR/kev.json"
  [ "$status" -eq 0 ]
}
