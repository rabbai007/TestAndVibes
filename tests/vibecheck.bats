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
  unset ANTHROPIC_API_KEY VIBECHECK_REVIEW_CMD VIBECHECK_EPSS_FILE VIBECHECK_KEV_FILE
  # Default-on network lookups must never reach the real service from a test:
  # a closed local port fails at once (tests that need EPSS use a file or a fake).
  export VIBECHECK_EPSS_URL="http://127.0.0.1:9/epss"
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
      case "$n" in claude|codex|gemini|gemini-api|agy|ant|trivy|osv-scanner|grype|npm|semgrep|trufflehog|gitleaks) continue;; esac
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
  [[ "$output" == *"--review-provider"* ]] || false
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
  [[ "$output" == *"review API returned HTTP 529 - retry 1/2"* ]] || false   # visible to the operator
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

# ── review pass: context coverage ──────────────────────────────────────────

@test "review: a file that does not fit the budget is listed and the pass is PARTIAL, not silently dropped" {
  head -c 600 /dev/zero | tr '\0' 'x' > "$APP/big.js"
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-budget 200 --review-cmd 'echo "[]"'
  [ "$status" -eq 0 ]
  [[ "$output" == *"did not fit the budget and were NOT reviewed"* ]] || false
  [[ "$output" == *"big.js (600 bytes)"* ]] || false
  [[ "$(jq -r '.coverage.passes[] | select(.pass=="review") | .detail' "$OUT/findings.json")" == *"PARTIAL: 1 file(s) NOT reviewed"*"big.js"* ]] || false
}

@test "review: a file over 120 KB is reviewed when it fits the budget (regression: hidden per-file cap)" {
  head -c 130000 /dev/zero | tr '\0' '\n' > "$APP/main.sh"
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "[]"'
  [ "$status" -eq 0 ]
  grep -qx 'main.sh' "$OUT/.review-files"
  [[ "$output" != *"PARTIAL"* ]] || false
}

@test "review: a skeptic sees the code around the claimed line, not the top of the file" {
  { for i in $(seq 1 999); do echo "// filler $i"; done
    echo 'const SKEPTIC_MARKER = db.find(req.query.id)'
    for i in $(seq 1 50); do echo "// tail $i"; done; } > "$APP/deep.js"
  cat > "$BIN/provider" <<'SH'
#!/usr/bin/env bash
in="$(cat)"
if printf '%s' "$in" | grep -q 'You are refuting'; then
  printf '%s' "$in" | grep -q 'SKEPTIC_MARKER' && echo CONFIRMED || echo REFUTED
else
  echo '[{"severity":"high","class":"broken-access-control","file":"deep.js","line":1000,"anchor":"SKEPTIC_MARKER","title":"IDOR deep in a large file","why":"no ownership check","confidence":"high"}]'
fi
SH
  chmod +x "$BIN/provider"
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd "$BIN/provider"
  [ "$status" -eq 0 ]
  [ "$(jq '[.active[] | select(.tool=="review")] | length' "$OUT/findings.json")" -eq 1 ]
}

# ── review pass: AI CLI providers (fake CLIs record argv, cwd and stdin) ────

# Installs a fake CLI named $1 that logs its argv (one per line), its cwd and its
# stdin, then prints a valid empty review. gemini answers in its JSON envelope.
fake_cli() {
  local name="$1"
  cat > "$BIN/$name" <<SH
#!/usr/bin/env bash
log="$BATS_TEST_TMPDIR/$name"
printf '%s\n' "\$@" > "\$log.argv"; pwd -P > "\$log.cwd"; cat > "\$log.stdin"
if [ "$name" = gemini ]; then echo '{"response":"[]","stats":{}}'; else echo '[]'; fi
SH
  chmod +x "$BIN/$name"
}
cli_run() { PATH="$BIN:$CLEAN_PATH" run "$VC" "${REVIEW_ONLY[@]}" --review "$@"; }
argv_has() { grep -qxF -- "$2" "$BATS_TEST_TMPDIR/$1.argv"; }

@test "provider claude: tools disabled, no MCP, effort passed, provider-default model, run outside the repo" {
  fake_cli claude
  cli_run
  [ "$status" -eq 0 ]
  [[ "$output" == *"provider: claude  model: (claude default)"* ]] || false
  argv_has claude -p
  # `--tools ""` - the flag followed by an empty argument
  grep -A1 -xF -- '--tools' "$BATS_TEST_TMPDIR/claude.argv" | sed -n 2p | grep -qx ''
  argv_has claude --strict-mcp-config
  argv_has claude high
  ! argv_has claude --model
  [ "$(cat "$BATS_TEST_TMPDIR/claude.cwd")" != "$(cd "$APP" && pwd -P)" ]
  [ -z "$(ls -A "$(cat "$BATS_TEST_TMPDIR/claude.cwd")" 2>/dev/null)" ] || [ ! -d "$(cat "$BATS_TEST_TMPDIR/claude.cwd")" ]
  grep -q 'FILE: server.js' "$BATS_TEST_TMPDIR/claude.stdin"
}

@test "provider codex: read-only sandbox, ephemeral, prompt on stdin, effort as config" {
  fake_cli codex
  cli_run
  [ "$status" -eq 0 ]
  [[ "$output" == *"provider: codex"* ]] || false
  argv_has codex exec
  grep -A1 -xF -- '--sandbox' "$BATS_TEST_TMPDIR/codex.argv" | grep -qx 'read-only'
  argv_has codex --ephemeral
  argv_has codex --skip-git-repo-check
  argv_has codex 'model_reasoning_effort="high"'
  argv_has codex -
  ! argv_has codex --model
  grep -q 'FILE: server.js' "$BATS_TEST_TMPDIR/codex.stdin"
}

@test "provider gemini: plan (read-only) approval mode, JSON envelope parsed, effort noted as ignored" {
  fake_cli gemini
  cli_run
  [ "$status" -eq 0 ]
  [[ "$output" == *"provider: gemini"*"not supported by gemini; ignored"* ]] || false
  [[ "$output" == *"no findings survived refutation"* ]] || false
  grep -A1 -xF -- '--approval-mode' "$BATS_TEST_TMPDIR/gemini.argv" | grep -qx plan
  argv_has gemini --skip-trust     # without it, plan is silently downgraded in an untrusted cwd
  grep -A1 -xF -- '--output-format' "$BATS_TEST_TMPDIR/gemini.argv" | grep -qx json
}

@test "provider: --review-model is passed through to the CLI" {
  fake_cli codex
  cli_run --review-model gpt-test-1
  [ "$status" -eq 0 ]
  grep -A1 -xF -- '--model' "$BATS_TEST_TMPDIR/codex.argv" | grep -qx gpt-test-1
  [[ "$output" == *"model: gpt-test-1"* ]] || false
}

@test "provider auto: claude before codex before gemini" {
  fake_cli codex; fake_cli gemini
  cli_run
  [[ "$output" == *"provider: codex"* ]] || false
  fake_cli claude
  cli_run
  [[ "$output" == *"provider: claude"* ]] || false
}

@test "provider pinned: --review-provider gemini is used even when claude is present" {
  fake_cli claude; fake_cli gemini
  cli_run --review-provider gemini
  [ "$status" -eq 0 ]
  [[ "$output" == *"provider: gemini"* ]] || false
  [ ! -e "$BATS_TEST_TMPDIR/claude.argv" ]
}

@test "provider pinned but missing fails closed, never falls back (exit 3)" {
  fake_cli claude
  cli_run --review-provider codex
  [ "$status" -eq 3 ]
  [[ "$output" == *"--review-provider codex is not available"* ]] || false
  [ ! -e "$BATS_TEST_TMPDIR/claude.argv" ]
}

@test "provider: a CLI that exits non-zero with no output fails closed and names the error" {
  printf '#!/bin/sh\necho "not logged in" >&2\nexit 1\n' > "$BIN/codex"; chmod +x "$BIN/codex"
  cli_run
  [ "$status" -eq 3 ]
  [[ "$output" == *"codex exited 1: not logged in"* ]] || false
}

@test "provider: unknown --review-provider is a usage error (exit 2)" {
  cli_run --review-provider bard
  [ "$status" -eq 2 ]
}

@test "provider gemini-api: stateless generate, prompt on --stdin, no agent flags needed" {
  fake_cli gemini-api
  cli_run
  [ "$status" -eq 0 ]
  [[ "$output" == *"provider: gemini-api"*"not supported by gemini-api; ignored"* ]] || false
  [[ "$output" == *"no findings survived refutation"* ]] || false
  argv_has gemini-api generate
  argv_has gemini-api --stdin
  argv_has gemini-api --stream=false
  argv_has gemini-api --no-interactive
  grep -q 'FILE: server.js' "$BATS_TEST_TMPDIR/gemini-api.stdin"
}

@test "provider auto: gemini-api is preferred over the enterprise-only gemini CLI" {
  fake_cli gemini; fake_cli gemini-api
  cli_run
  [[ "$output" == *"provider: gemini-api"* ]] || false
  [ ! -e "$BATS_TEST_TMPDIR/gemini.argv" ]
}

@test "provider gemini: if the CLI downgrades the read-only approval mode, the review is discarded (exit 3)" {
  cat > "$BIN/gemini" <<'SH'
#!/usr/bin/env bash
cat >/dev/null
echo 'Approval mode overridden to "default" because the current folder is not trusted.' >&2
echo '{"response":"[]"}'
SH
  chmod +x "$BIN/gemini"
  cli_run --review-provider gemini
  [ "$status" -eq 3 ]
  [[ "$output" == *"overrode the read-only approval mode"*"review discarded"* ]] || false
  [[ "$output" != *"no findings survived"* ]] || false
}

@test "provider gemini: an individual account (IneligibleTierError) points at gemini-api" {
  cat > "$BIN/gemini" <<'SH'
#!/usr/bin/env bash
cat >/dev/null
echo 'Error authenticating: IneligibleTierError: This client is no longer supported for Gemini Code Assist for individuals.' >&2
exit 55
SH
  chmod +x "$BIN/gemini"
  cli_run --review-provider gemini
  [ "$status" -eq 3 ]
  [[ "$output" == *"gemini exited 55"*"use --review-provider gemini-api with GEMINI_API_KEY"* ]] || false
}

# ── review pass: CLI transient-failure retries ─────────────────────────────

# A fake gemini-api that fails with the stderr/exit given for its first N calls
# ($FAKE_FAILS), then answers. Counts calls in $BATS_TEST_TMPDIR/calls.
flaky_gemini_api() {  # $1 = exit code, $2 = stderr text
  cat > "$BIN/gemini-api" <<SH
#!/usr/bin/env bash
cat >/dev/null
n=\$(( \$(cat "$BATS_TEST_TMPDIR/calls" 2>/dev/null || echo 0) + 1 )); echo "\$n" > "$BATS_TEST_TMPDIR/calls"
if [ "\$n" -le "\${FAKE_FAILS:-0}" ]; then echo "$2" >&2; exit $1; fi
echo '[]'
SH
  chmod +x "$BIN/gemini-api"
}
retry_run() { VIBECHECK_REVIEW_RETRY_DELAY=0 cli_run --review-provider gemini-api "$@"; }

@test "cli retry: a transient 503 (high demand) is retried and the review completes" {
  flaky_gemini_api 1 'Error (server_error): gemini-3.8-flash is currently experiencing high demand. HTTP status: 503'
  FAKE_FAILS=1 retry_run
  [ "$status" -eq 0 ]
  [[ "$output" == *"failed transiently (exit 1) - retry 1/2"* ]] || false
  [[ "$output" == *"no findings survived refutation"* ]] || false
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 2 ]
}

@test "cli retry: retries are bounded, then fail closed naming the error and attempts" {
  flaky_gemini_api 1 'HTTP status: 503 high demand'
  FAKE_FAILS=99 VIBECHECK_REVIEW_RETRIES=3 retry_run
  [ "$status" -eq 3 ]
  [[ "$output" == *"gemini-api exited 1 after 3 attempts: HTTP status: 503"* ]] || false
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 3 ]
}

@test "cli retry: an auth failure is not retried" {
  flaky_gemini_api 3 'Error (unauthenticated): API key not valid. HTTP status: 401'
  FAKE_FAILS=99 retry_run
  [ "$status" -eq 3 ]
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
}

@test "cli retry: a non-transient runtime error is not retried" {
  flaky_gemini_api 1 'Error: model output blocked by safety settings'
  FAKE_FAILS=99 retry_run
  [ "$status" -eq 3 ]
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
}

@test "cli quota: a model with no quota on this tier (limit: 0) is not retried and says billing" {
  flaky_gemini_api 1 'Error (resource_exhausted): You exceeded your current quota, please check your plan and billing details. Quota exceeded for metric: generate_content_free_tier_input_token_count, limit: 0, model: gemini-4-argon. HTTP status: 429'
  FAKE_FAILS=99 retry_run --review-model gemini-4-argon
  [ "$status" -eq 3 ]
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
  [[ "$output" == *"QUOTA/BILLING, not retried"*"gemini-4-argon"* ]] || false
}

@test "cli quota: a per-minute rate limit is retried after the delay the API asks for" {
  flaky_gemini_api 1 'Error (resource_exhausted): Quota exceeded for metric: input_token_count per minute. Please retry in 1.2s. HTTP status: 429'
  FAKE_FAILS=1 retry_run
  [ "$status" -eq 0 ]
  [[ "$output" == *"retry 1/2 in 2s"* ]] || false        # 1.2s hinted -> 1 + 1 s
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 2 ]
}

# ── --diff: what a pull request changed must be what gets reviewed and gated ─

# A git repo where server.js (name-prioritised) is unchanged and zzz.js is the
# file the "PR" changed, plus a lockfile the PR also changed.
diff_repo() {
  git -C "$APP" init -q -b main
  git -C "$APP" -c user.email=t@t -c user.name=t add -A
  git -C "$APP" -c user.email=t@t -c user.name=t commit -q -m base
  git -C "$APP" checkout -q -b pr
  printf 'export const x = req.query.id\n' > "$APP/zzz.js"
  printf 'demo==1.0\n' > "$APP/requirements.txt"
  git -C "$APP" -c user.email=t@t -c user.name=t add -A
  git -C "$APP" -c user.email=t@t -c user.name=t commit -q -m pr
}

@test "diff: the review puts the PR's changed files first in its budget (regression)" {
  # Order decides what fits: server.js (~100 B, name-prioritised) and zzz.js
  # (~150 B, changed by the PR) cannot both fit in 200 B. Before the fix the
  # changed list did not exist yet, so server.js won and the PR's file was cut.
  head -c 40 /dev/zero | tr '\0' 'x' >> "$APP/server.js"
  diff_repo
  head -c 120 /dev/zero | tr '\0' 'x' >> "$APP/zzz.js"
  git -C "$APP" -c user.email=t@t -c user.name=t commit -qam grow
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-budget 200 --review-cmd 'echo "[]"' --diff main
  grep -qx 'zzz.js' "$OUT/.review-files"                    # the PR's file is reviewed...
  ! grep -qx 'server.js' "$OUT/.review-files"               # ...ahead of the name-prioritised one
  [ "$(grep -c . "$OUT/.review-files")" -eq "$(sort -u "$OUT/.review-files" | grep -c .)" ]   # no duplicates
  [[ "$output" == *"server.js"*"bytes"* ]] || false          # the unchanged one is listed as skipped
}

@test "diff: a grype-only CVE in a changed lockfile gates the PR (regression: placeholder file path)" {
  kev_setup
  printf '{"Results":[{"Target":"requirements.txt","Vulnerabilities":[]}]}' > "$FAKE_TRIVY_JSON"
  cat > "$BIN/grype" <<'SH'
#!/usr/bin/env bash
[ "$1" = version ] && { echo "Version: 0.0.0-fake"; exit 0; }
out=""; while [ $# -gt 0 ]; do [ "$1" = "--file" ] && out="$2"; shift; done
cat > "$out" <<'JSON'
{"matches":[{"vulnerability":{"id":"CVE-2099-0002","severity":"High","dataSource":""},
  "artifact":{"name":"demo","version":"1.0","locations":[{"path":"/requirements.txt"}]}}]}
JSON
SH
  chmod +x "$BIN/grype"
  rm -f "$APP/requirements.txt"; diff_repo
  kev_run --dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review --no-kev \
          --skip-secrets --skip-sast --skip-iac --diff main
  [ "$status" -eq 1 ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0002") | .file' "$OUT/findings.json")" = "requirements.txt" ]
}

# ── second-model review findings (fail-open paths) ─────────────────────────

@test "diff: a changed symlink to a host file is never sent to the review model" {
  printf 'TOP-SECRET-HOST-FILE\n' > "$BATS_TEST_TMPDIR/host-secret"
  diff_repo
  ln -s "$BATS_TEST_TMPDIR/host-secret" "$APP/creds.js"
  git -C "$APP" -c user.email=t@t -c user.name=t add -A
  git -C "$APP" -c user.email=t@t -c user.name=t commit -q -m link
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "[]"' --diff main
  ! grep -q 'TOP-SECRET-HOST-FILE' "$OUT/.review-context.txt"
  ! grep -qx 'creds.js' "$OUT/.review-files"
  [[ "$output" == *"creds.js is a symlink - NOT sent"* ]] || false
}

@test "diff: a ref with no merge base fails closed (exit 3), it does not gate on nothing" {
  diff_repo
  git -C "$APP" checkout -q --orphan lonely
  git -C "$APP" -c user.email=t@t -c user.name=t commit -q -m unrelated
  git -C "$APP" checkout -q pr
  run "$VC" "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "[]"' --diff lonely
  [ "$status" -eq 3 ]
  [[ "$output" == *"cannot diff against 'lonely'"* ]] || false
}

@test "deps: the same CVE in two lockfiles is two findings; the changed one gates the PR" {
  kev_setup
  mkdir -p "$APP/svc"; printf 'demo==1.0\n' > "$APP/svc/requirements.txt"
  git -C "$APP" init -q -b main
  git -C "$APP" -c user.email=t@t -c user.name=t add -A
  git -C "$APP" -c user.email=t@t -c user.name=t commit -q -m base
  git -C "$APP" checkout -q -b pr
  printf 'demo==1.0\n# touched\n' > "$APP/svc/requirements.txt"
  git -C "$APP" -c user.email=t@t -c user.name=t commit -qam pr
  # The unchanged lockfile is listed first, so a (CVE, package) dedup kept it.
  cat > "$FAKE_TRIVY_JSON" <<'JSON'
{"Results":[
 {"Target":"requirements.txt","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0003","PkgName":"demo","InstalledVersion":"1.0","Severity":"HIGH","Title":"t"}]},
 {"Target":"svc/requirements.txt","Vulnerabilities":[{"VulnerabilityID":"CVE-2099-0003","PkgName":"demo","InstalledVersion":"1.0","Severity":"HIGH","Title":"t"}]}]}
JSON
  kev_run "${DEPS_ONLY[@]}" --no-kev --fail-on high --diff main
  [ "$status" -eq 1 ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0003") | .file' "$OUT/findings.json")" = "svc/requirements.txt" ]
}

@test "deps: an npm audit error document is not a completed scan (exit 3)" {
  printf '{"name":"a","lockfileVersion":3}\n' > "$APP/package-lock.json"
  printf '{"name":"a"}\n' > "$APP/package.json"
  cat > "$BIN/npm" <<'SH'
#!/usr/bin/env bash
[ "$1" = "--version" ] && { echo 10.0.0; exit 0; }
echo '{"error":{"code":"E401","summary":"Unable to authenticate"}}'; exit 1
SH
  chmod +x "$BIN/npm"
  PATH="$BIN:$CLEAN_PATH" run "$VC" --dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review --no-kev \
          --skip-secrets --skip-sast --skip-iac
  [ "$status" -eq 3 ]
  [[ "$output" == *"npm audit did not complete - Unable to authenticate"* ]] || false
}

@test "secrets: a trufflehog crash with no output is an error (exit 3), not '0 secrets'" {
  printf '#!/usr/bin/env bash\necho "fatal: boom" >&2; exit 1\n' > "$BIN/trufflehog"
  chmod +x "$BIN/trufflehog"
  PATH="$BIN:$CLEAN_PATH" run "$VC" --dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review \
          --skip-sast --skip-deps --skip-iac
  [ "$status" -eq 3 ]
  [[ "$output" == *"trufflehog scan failed: filesystem(exit 1)"* ]] || false
}

# ── assistant guidance: AGENTS.md and the skill must not drift from the CLI ──

@test "skill: frontmatter has the name and description Agent Skills requires" {
  local s="$BATS_TEST_DIRNAME/../.agents/skills/vibecheck/SKILL.md"
  [ "$(sed -n 1p "$s")" = "---" ]
  sed -n '2,/^---$/p' "$s" | grep -qx 'name: vibecheck'
  sed -n '2,/^---$/p' "$s" | grep -q '^description: .\{40,\}'
}

@test "skill + AGENTS.md: every vibecheck flag they tell an assistant to use exists" {
  local help flag missing=""
  help="$("$VC" --help)"
  for flag in $(grep -ohE -- '--[a-z][a-z-]*[a-z*]' \
                  "$BATS_TEST_DIRNAME/../.agents/skills/vibecheck/SKILL.md" \
                  "$BATS_TEST_DIRNAME/../AGENTS.md" | sed 's/\*$//' | sort -u); do
    printf '%s\n' "$help" | grep -qF -- "$flag" || missing="$missing $flag"
  done
  [ -z "$missing" ] || { echo "not in --help:$missing"; false; }
}

# ── EPSS: exploit probability annotates, never changes severity ────────────

epss_csv() {  # the FIRST daily CSV shape; CVE-2099-0002 deliberately unscored
  printf '#model_version:v2099.01.01,score_date:%sT00:00:00Z\ncve,epss,percentile\nCVE-2099-0001,0.84887,0.99712\nCVE-1999-0001,0.01,0.5\n' \
    "$(date -u +%Y-%m-%d)" > "$BATS_TEST_TMPDIR/epss.csv"
}

@test "epss: a CVE is annotated with score and percentile; severity and the gate are unchanged" {
  kev_setup; epss_csv
  kev_run "${DEPS_ONLY[@]}" --no-kev --epss-file "$BATS_TEST_TMPDIR/epss.csv"
  [ "$status" -eq 0 ]                                   # two mediums, --fail-on high: still passes
  local f="$OUT/findings.json"
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .epss.score' "$f")" = "0.84887" ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .severity' "$f")" = "medium" ]
  [[ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .title' "$f")" == *"[EPSS 84.9%, percentile 99.7]" ]] || false
  [ "$(jq -r '.coverage.passes[] | select(.pass=="epss") | .status' "$f")" = "ok" ]
}

@test "epss: a CVE FIRST has not scored gets no annotation (unknown, not 0%)" {
  kev_setup; epss_csv
  kev_run "${DEPS_ONLY[@]}" --no-kev --epss-file "$BATS_TEST_TMPDIR/epss.csv"
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0002") | has("epss")' "$OUT/findings.json")" = "false" ]
  [[ "$(jq -r '.active[] | select(.rule=="CVE-2099-0002") | .title' "$OUT/findings.json")" != *EPSS* ]] || false
}

@test "epss: a gzipped daily file works" {
  kev_setup; epss_csv; gzip "$BATS_TEST_TMPDIR/epss.csv"
  kev_run "${DEPS_ONLY[@]}" --no-kev --epss-file "$BATS_TEST_TMPDIR/epss.csv.gz"
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .epss.percentile' "$OUT/findings.json")" = "0.99712" ]
}

@test "epss: --epss-file that does not exist, or is not the FIRST CSV, fails closed (exit 3)" {
  kev_setup
  kev_run "${DEPS_ONLY[@]}" --no-kev --epss-file "$BATS_TEST_TMPDIR/nope.csv"
  [ "$status" -eq 3 ]
  printf 'not,a,feed\n' > "$BATS_TEST_TMPDIR/bad.csv"
  kev_run "${DEPS_ONLY[@]}" --no-kev --epss-file "$BATS_TEST_TMPDIR/bad.csv"
  [ "$status" -eq 3 ]
  [[ "$output" == *"not the FIRST CSV"* ]] || false
}

@test "epss: default-on with the API unreachable warns and records 'NOT checked'; explicit --epss fails closed" {
  kev_setup
  kev_run "${DEPS_ONLY[@]}" --no-kev
  [ "$status" -eq 0 ]
  [[ "$output" == *"EPSS NOT checked"* ]] || false
  [ "$(jq -r '.coverage.passes[] | select(.pass=="epss") | .status' "$OUT/findings.json")" = "skipped" ]
  kev_run "${DEPS_ONLY[@]}" --no-kev --epss
  [ "$status" -eq 3 ]
}

@test "epss: API path batches CVEs and parses FIRST's response" {
  kev_setup
  cat > "$BIN/curl" <<'SH'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -w|--max-time|--retry|--retry-delay) shift 2;; -*) shift;; *) url="$1"; shift;; esac; done
echo "$url" >> "$FAKE_CURL_LOG"
printf '{"status":"OK","status-code":200,"data":[{"cve":"CVE-2099-0002","epss":"0.5","percentile":"0.9","date":"2099-01-01"}]}' > "$out"
printf 200
SH
  chmod +x "$BIN/curl"; export FAKE_CURL_LOG="$BATS_TEST_TMPDIR/curl.log"
  VIBECHECK_EPSS_URL="https://epss.invalid/v1" kev_run "${DEPS_ONLY[@]}" --no-kev --epss
  [ "$status" -eq 0 ]
  grep -qx 'https://epss.invalid/v1?cve=CVE-2099-0001,CVE-2099-0002' "$FAKE_CURL_LOG"
  [ "$(grep -c . "$FAKE_CURL_LOG")" -eq 1 ]               # one batch, no empty trailing request
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0002") | .epss.score' "$OUT/findings.json")" = "0.5" ]
}

# ── --image: what was built, not just the Dockerfile ───────────────────────

image_setup() {  # fake trivy: image "old:1" is EOL with a CVE and a secret; "clean:1" is clean; anything else fails
  cat > "$BIN/trivy" <<'SH'
#!/usr/bin/env bash
case " $* " in *" --version "*) echo "Version: 0.0.0-fake"; exit 0;; esac
[ "$1" = image ] || exit 0
out=""; ref=""; while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift 2;; --*) [ "$1" = --quiet ] && shift || shift 2;; *) ref="$1"; shift;; esac; done
case "$ref" in
  old:1) cat > "$out" <<'JSON'
{"ArtifactName":"old:1","Metadata":{"ImageID":"sha256:0123456789abcdef","OS":{"Family":"alpine","Name":"3.12.12","EOSL":true}},
 "Results":[{"Target":"old:1 (alpine 3.12.12)","Vulnerabilities":[
   {"VulnerabilityID":"CVE-2099-0001","PkgName":"zlib","InstalledVersion":"1.2","FixedVersion":"1.3","Severity":"MEDIUM","Title":"zlib overflow"}]},
  {"Target":"/app/.env","Class":"secret","Secrets":[{"RuleID":"aws-access-key-id","Severity":"CRITICAL","Title":"AWS Access Key ID","StartLine":3}]}]}
JSON
  ;;
  clean:1) printf '{"ArtifactName":"clean:1","Metadata":{"OS":{"Family":"alpine","Name":"3.22.0"}},"Results":[]}' > "$out";;
  *) echo "FATAL run error: could not parse reference: $ref" >&2; exit 1;;
esac
SH
  chmod +x "$BIN/trivy"
  IMG_ONLY=(--dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review --no-kev --no-epss
            --skip-secrets --skip-sast --skip-deps --skip-iac)
}

@test "image: CVEs, a secret in a layer and an end-of-life base OS are reported against the image" {
  image_setup
  kev_run "${IMG_ONLY[@]}" --image old:1
  [ "$status" -eq 1 ]                                    # the critical secret gates
  local f="$OUT/findings.json"
  [ "$(jq -r '[.active[] | select(.file=="image:old:1")] | length' "$f")" -eq 3 ]
  [ "$(jq -r '.active[] | select(.rule=="image.eol-os") | .severity' "$f")" = "high" ]
  [ "$(jq -r '.active[] | select(.rule=="image-secret.aws-access-key-id") | .severity' "$f")" = "critical" ]
  [[ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .title' "$f")" == *"zlib@1.2"*"(fixed in 1.3)"* ]] || false
  [[ "$output" == *"baked into a layer - rotate them"* ]] || false
}

@test "image: a clean image passes and records an ok image pass" {
  image_setup
  kev_run "${IMG_ONLY[@]}" --image clean:1
  [ "$status" -eq 0 ]
  [ "$(jq -r '.coverage.passes[] | select(.pass=="image") | .status' "$OUT/findings.json")" = "ok" ]
}

@test "image: one image that cannot be scanned fails closed (exit 3), even if another scanned" {
  image_setup
  kev_run "${IMG_ONLY[@]}" --image clean:1 --image missing:9
  [ "$status" -eq 3 ]
  [[ "$output" == *"missing:9"*"could not parse reference"* ]] || false
}

@test "image: --image without trivy is an error (exit 3); no --image is a recorded skip" {
  PATH="$CLEAN_PATH" run "$VC" --dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review \
     --skip-secrets --skip-sast --skip-deps --skip-iac --image clean:1
  [ "$status" -eq 3 ]
  image_setup
  kev_run "${IMG_ONLY[@]}"
  [ "$(jq -r '.coverage.passes[] | select(.pass=="image") | .detail' "$OUT/findings.json")" = "no --image" ]
}

@test "image: a KEV-listed CVE in an image is raised to critical, even with --skip-deps" {
  kev_setup; image_setup                  # kev_setup writes kev.json; image_setup's trivy wins
  kev_run --dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review --no-epss \
          --skip-secrets --skip-sast --skip-deps --skip-iac \
          --kev-file "$BATS_TEST_TMPDIR/kev.json" --image old:1
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .severity' "$OUT/findings.json")" = "critical" ]
  [ "$(jq -r '.active[] | select(.rule=="CVE-2099-0001") | .kev.cve' "$OUT/findings.json")" = "CVE-2099-0001" ]
}

@test "image: --diff never scopes image findings out (they describe the artifact, not a file)" {
  image_setup; diff_repo
  kev_run "${IMG_ONLY[@]}" --image old:1 --diff main
  [ "$status" -eq 1 ]
  [ "$(jq -r '[.out_of_scope[] | select(.tool=="image")] | length' "$OUT/findings.json")" -eq 0 ]
}

# ── --licenses / --sbom ────────────────────────────────────────────────────

lic_setup() {  # fake osv-scanner in allowlist mode: lists every package not on the list
  printf 'a==1\n' > "$APP/requirements.txt"
  cat > "$BIN/osv-scanner" <<'SH'
#!/usr/bin/env bash
[ "$1" = "--version" ] && { echo "osv-scanner version: 0.0.0-fake"; exit 0; }
out=""; allow=""
for a in "$@"; do case "$a" in --licenses=*) allow="${a#--licenses=}";; esac; done
while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done
echo "$allow" > "$FAKE_OSV_ALLOW"
[ "${FAKE_OSV_MODE:-}" = crash ] && { echo "boom" >&2; exit 127; }
cat > "$out" <<JSON
{"results":[{"source":{"path":"$FAKE_APP/requirements.txt"},"packages":[
  {"package":{"name":"agpl-lib","version":"1.0"},"licenses":["AGPL-3.0-only"]},
  {"package":{"name":"gpl-lib","version":"2.0"},"licenses":["GPL-3.0-or-later"]},
  {"package":{"name":"dual","version":"3.0"},"licenses":["MIT OR GPL-3.0-only"]},
  {"package":{"name":"custom","version":"4.0"},"licenses":["non-standard"]},
  {"package":{"name":"fine","version":"5.0"},"licenses":["Apache-2.0"]}]}],
 "license_summary":[{"name":"x","count":6}]}
JSON
exit 1
SH
  chmod +x "$BIN/osv-scanner"
  export FAKE_APP="$APP" FAKE_OSV_ALLOW="$BATS_TEST_TMPDIR/allow"
  LIC_ONLY=(--dir "$APP" --out "$OUT" --no-baseline --no-pdf --no-review
            --skip-secrets --skip-sast --skip-deps --skip-iac)
}

@test "licenses: default policy - AGPL high, GPL and custom medium, permissive and MIT-OR-GPL pass" {
  lic_setup
  kev_run "${LIC_ONLY[@]}" --licenses
  [ "$status" -eq 1 ]                                         # AGPL is high: gates
  local f="$OUT/findings.json"
  [ "$(jq -r '.active[] | select(.title|startswith("agpl-lib")) | .severity' "$f")" = "high" ]
  [ "$(jq -r '.active[] | select(.title|startswith("gpl-lib")) | .severity' "$f")" = "medium" ]
  [ "$(jq -r '.active[] | select(.title|startswith("custom")) | .severity' "$f")" = "medium" ]
  [ "$(jq -r '[.active[] | select(.title|startswith("dual") or startswith("fine"))] | length' "$f")" -eq 0 ]
  [ "$(jq -r '.active[] | select(.title|startswith("agpl-lib")) | .file' "$f")" = "requirements.txt" ]
  [ "$(cat "$FAKE_OSV_ALLOW")" = "0BSD" ]                    # allowlist mode: every package listed
}

@test "licenses: --license-allow replaces the policy and is passed to osv-scanner" {
  lic_setup
  kev_run "${LIC_ONLY[@]}" --license-allow 'MIT, Apache-2.0'
  [ "$(cat "$FAKE_OSV_ALLOW")" = "MIT,Apache-2.0" ]
  [ "$(jq -r '[.active[] | select(.tool=="license" and .severity=="high")] | length' "$OUT/findings.json")" -eq 3 ]  # agpl, gpl, custom
}

@test "licenses: an osv-scanner failure, or no osv-scanner, is an error (exit 3)" {
  lic_setup
  FAKE_OSV_MODE=crash kev_run "${LIC_ONLY[@]}" --licenses
  [ "$status" -eq 3 ]
  rm "$BIN/osv-scanner"
  kev_run "${LIC_ONLY[@]}" --licenses
  [ "$status" -eq 3 ]
  [[ "$output" == *"--licenses needs osv-scanner"* ]] || false
}

@test "sbom: --sbom writes a CycloneDX file; a trivy failure is an error (exit 3)" {
  cat > "$BIN/trivy" <<'SH'
#!/usr/bin/env bash
case " $* " in *" --version "*) echo "Version: 0.0.0-fake"; exit 0;; esac
out=""; while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done
[ -n "${FAKE_TRIVY_FAIL:-}" ] && exit 1
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]}' > "$out"
SH
  chmod +x "$BIN/trivy"
  kev_run "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "[]"' --sbom
  [ "$status" -eq 0 ]
  [ "$(jq -r .bomFormat "$OUT/sbom.cdx.json")" = "CycloneDX" ]
  FAKE_TRIVY_FAIL=1 kev_run "${REVIEW_ONLY[@]}" --review --review-cmd 'echo "[]"' --sbom
  [ "$status" -eq 3 ]
}
