#!/usr/bin/env bash
#
# VibeCheck — portable, non-destructive security audit for web apps.
#
#   Static analysis:  secrets · SAST · dependency CVEs · IaC/container misconfig
#   Dynamic (opt-in): HTTP security headers · TLS · cookie flags  (your URL only)
#
# Wraps best-in-class OSS scanners (semgrep, trivy, grype, trufflehog, gitleaks,
# npm/pip/osv audit) behind one command, auto-detects the stack, degrades
# gracefully when a tool is absent, and emits a consolidated report + a CI-
# friendly exit code.
#
# LEGAL: run only against code and systems you own or are explicitly authorized
# to test. The dynamic checks are read-only (a GET + TLS handshake) — no
# exploitation, no payloads. You are responsible for how you use this.
#
# Usage:
#   ./vibecheck.sh                         # static scan of the current dir
#   ./vibecheck.sh --dir ../myapp          # scan another directory
#   ./vibecheck.sh --url https://me.app    # + safe dynamic header/TLS checks
#   ./vibecheck.sh --all --url https://me.app
#   ./vibecheck.sh --fail-on critical      # CI gate threshold
#   ./vibecheck.sh --install               # install the underlying scanners
#
# Exit codes: 0 = clean at/under threshold · 1 = findings over threshold · 2 = error
set -uo pipefail

VERSION="0.1.0"
TARGET="."
URL=""
DYNAMIC=0
FAIL_ON="high"     # never | low | medium | high | critical | any
OUTDIR="vibecheck-report"
SELF_INSTALL=0

# ── pretty output ──
if [ -t 1 ]; then C_R=$'\033[31m'; C_Y=$'\033[33m'; C_G=$'\033[32m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'; C_BOLD=$'\033[1m'
else C_R=; C_Y=; C_G=; C_B=; C_D=; C_0=; C_BOLD=; fi
say()  { printf '%s\n' "$*"; }
head2(){ printf '\n%s▶ %s%s\n' "$C_B$C_BOLD" "$*" "$C_0"; }
ok()   { printf '  %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$C_R" "$C_0" "$*"; }
skip() { printf '  %s— %s (skipped: %s)%s\n' "$C_D" "$1" "$2" "$C_0"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ── args ──
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) TARGET="$2"; shift 2;;
    --url) URL="$2"; DYNAMIC=1; shift 2;;
    --dynamic) DYNAMIC=1; shift;;
    --all) DYNAMIC=1; shift;;
    --fail-on) FAIL_ON="$2"; shift 2;;
    --out) OUTDIR="$2"; shift 2;;
    --install) SELF_INSTALL=1; shift;;
    -h|--help) usage;;
    *) bad "unknown arg: $1"; exit 2;;
  esac
done

# ── self-install ──
if [ "$SELF_INSTALL" = 1 ]; then
  head2 "Installing scanners"
  if have brew; then
    brew install trivy grype trufflehog gitleaks 2>/dev/null || true
  else
    say "  Homebrew not found. Install manually:"
    say "    trivy    : https://aquasecurity.github.io/trivy/"
    say "    grype    : https://github.com/anchore/grype#installation"
    say "    trufflehog: https://github.com/trufflesecurity/trufflehog#installation"
    say "    gitleaks : https://github.com/gitleaks/gitleaks#installing"
  fi
  if have pipx; then pipx install semgrep 2>/dev/null || true
  elif have pip3; then pip3 install --user semgrep 2>/dev/null || true
  else say "    semgrep  : pipx install semgrep  (https://semgrep.dev)"; fi
  ok "install pass complete (re-run without --install to scan)"
  exit 0
fi

[ -d "$TARGET" ] || { bad "target dir not found: $TARGET"; exit 2; }
TARGET="$(cd "$TARGET" && pwd)"
mkdir -p "$OUTDIR"
REPORT="$OUTDIR/report.md"
: > "$REPORT"

# ── severity accounting ──
CRIT=0; HIGH=0; MED=0; LOW=0
add() { case "$1" in crit) CRIT=$((CRIT+1));; high) HIGH=$((HIGH+1));; med) MED=$((MED+1));; low) LOW=$((LOW+1));; esac; }
sect() { printf '\n## %s\n\n' "$1" >> "$REPORT"; }
line() { printf '%s\n' "$*" >> "$REPORT"; }

STAMP="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo now)"
{ echo "# VibeCheck security report"; echo; echo "- Target: \`$TARGET\`"; echo "- Date: $STAMP";
  [ -n "$URL" ] && echo "- Dynamic target: $URL"; echo "- Tool: VibeCheck v$VERSION"; } >> "$REPORT"

say "${C_BOLD}VibeCheck v$VERSION${C_0}  —  $TARGET"

# ── stack detection ──
head2 "Stack detection"
STACK=""
det() { [ -e "$TARGET/$1" ] && { STACK="$STACK $2"; ok "$2 ($1)"; }; }
det package.json node
det requirements.txt python; det pyproject.toml python; det Pipfile python
det go.mod go
det Cargo.toml rust
det composer.json php
det Gemfile ruby
det Dockerfile docker
det docker-compose.yml docker-compose
ls "$TARGET"/*.tf >/dev/null 2>&1 && { STACK="$STACK terraform"; ok "terraform (*.tf)"; }
[ -d "$TARGET/.git" ] && { STACK="$STACK git"; ok "git repo"; }
[ -z "$STACK" ] && warn "no known stack markers found — running generic checks"

# ── 1. secret scanning ──
head2 "1. Secret scanning"
sect "Secrets"
if have trufflehog; then
  if [ -d "$TARGET/.git" ]; then
    n=$(trufflehog git "file://$TARGET" --only-verified --json 2>/dev/null | grep -c . || true)
    [ "$n" -gt 0 ] && { bad "trufflehog: $n VERIFIED secret(s) in git history"; add crit; line "- **CRITICAL** trufflehog: $n verified secret(s) in git history"; } \
                   || ok "trufflehog: 0 verified secrets in git history"
  fi
  nf=$(trufflehog filesystem "$TARGET" --only-verified --json 2>/dev/null | grep -c . || true)
  [ "$nf" -gt 0 ] && { warn "trufflehog: $nf verified secret(s) in working tree (check .gitignore)"; add high; line "- **HIGH** trufflehog: $nf verified secret(s) in the working tree"; } \
                  || ok "trufflehog: 0 verified secrets in working tree"
elif have gitleaks; then
  if gitleaks detect --source "$TARGET" --no-banner -r "$OUTDIR/gitleaks.json" >/dev/null 2>&1; then ok "gitleaks: no secrets"; else
    n=$(grep -c '"RuleID"' "$OUTDIR/gitleaks.json" 2>/dev/null || echo "?"); bad "gitleaks: $n potential secret(s)"; add high; line "- **HIGH** gitleaks: $n potential secret(s)"; fi
else skip "secret scan" "install trufflehog or gitleaks"; line "- _skipped: no secret scanner installed_"; fi

# ── 2. SAST ──
head2 "2. Static analysis (SAST)"
sect "SAST"
if have semgrep; then
  semgrep scan --config=auto --json --output="$OUTDIR/semgrep.json" \
    --exclude=node_modules --exclude=dist --exclude=build --exclude=vendor --quiet "$TARGET" >/dev/null 2>&1 || true
  if [ -f "$OUTDIR/semgrep.json" ]; then
    e=$(grep -o '"severity": *"ERROR"' "$OUTDIR/semgrep.json" | wc -l | tr -d ' ')
    w=$(grep -o '"severity": *"WARNING"' "$OUTDIR/semgrep.json" | wc -l | tr -d ' ')
    [ "$e" -gt 0 ] && { bad "semgrep: $e error-level finding(s)"; for i in $(seq 1 "$e"); do add high; done; line "- **HIGH** semgrep: $e ERROR-level finding(s) — see $OUTDIR/semgrep.json"; } || ok "semgrep: 0 error-level findings"
    [ "$w" -gt 0 ] && { warn "semgrep: $w warning(s)"; add low; line "- **LOW** semgrep: $w WARNING-level finding(s)"; }
  fi
else skip "SAST" "install semgrep (pipx install semgrep)"; line "- _skipped: semgrep not installed_"; fi

# ── 3. dependency CVEs ──
head2 "3. Dependency vulnerabilities"
sect "Dependencies"
DEP_DONE=0
if have trivy; then
  trivy fs --scanners vuln --severity HIGH,CRITICAL --skip-dirs node_modules --quiet \
    --format json --output "$OUTDIR/trivy-deps.json" "$TARGET" >/dev/null 2>&1 || true
  if [ -f "$OUTDIR/trivy-deps.json" ]; then
    c=$(grep -o '"Severity": *"CRITICAL"' "$OUTDIR/trivy-deps.json" | wc -l | tr -d ' ')
    h=$(grep -o '"Severity": *"HIGH"' "$OUTDIR/trivy-deps.json" | wc -l | tr -d ' ')
    [ "$c" -gt 0 ] && { bad "trivy: $c CRITICAL dependency CVE(s)"; for i in $(seq 1 "$c"); do add crit; done; line "- **CRITICAL** trivy: $c critical dependency CVE(s)"; }
    [ "$h" -gt 0 ] && { warn "trivy: $h HIGH dependency CVE(s)"; for i in $(seq 1 "$h"); do add high; done; line "- **HIGH** trivy: $h high dependency CVE(s)"; }
    [ "$c" = 0 ] && [ "$h" = 0 ] && ok "trivy: 0 HIGH/CRITICAL dependency CVEs"
    DEP_DONE=1
  fi
fi
if [ "$DEP_DONE" = 0 ]; then
  case " $STACK " in
    *" node "*) if have npm; then (cd "$TARGET" && npm audit --omit=dev --audit-level=high >/dev/null 2>&1) && ok "npm audit: clean (prod, ≥high)" || { warn "npm audit: high/critical prod CVEs"; add high; line "- **HIGH** npm audit reported high/critical production CVEs"; }; fi;;
  esac
  have osv-scanner && { osv-scanner --recursive "$TARGET" >/dev/null 2>&1 && ok "osv-scanner: clean" || { warn "osv-scanner: vulnerabilities found"; add high; line "- **HIGH** osv-scanner found vulnerabilities"; }; }
  [ -z "${STACK// /}" ] && skip "dependency scan" "install trivy or osv-scanner"
fi

# ── 4. IaC / container misconfig ──
head2 "4. IaC & container misconfig"
sect "IaC / Containers"
if have trivy && { case " $STACK " in *docker*|*terraform*) true;; *) false;; esac; }; then
  trivy config --severity HIGH,CRITICAL --quiet --format json --output "$OUTDIR/trivy-iac.json" "$TARGET" >/dev/null 2>&1 || true
  if [ -f "$OUTDIR/trivy-iac.json" ]; then
    m=$(grep -o '"Severity": *"HIGH"\|"Severity": *"CRITICAL"' "$OUTDIR/trivy-iac.json" | wc -l | tr -d ' ')
    [ "$m" -gt 0 ] && { warn "trivy config: $m HIGH/CRITICAL misconfig(s)"; add med; line "- **MEDIUM** trivy config: $m high/critical IaC misconfiguration(s)"; } || ok "trivy config: 0 HIGH/CRITICAL misconfigs"
  fi
else skip "IaC scan" "no Dockerfile/terraform, or trivy missing"; fi

# ── 5. dynamic (opt-in, safe) ──
if [ "$DYNAMIC" = 1 ] && [ -n "$URL" ]; then
  head2 "5. Dynamic checks (read-only) — $URL"
  sect "Dynamic — $URL"
  hdrs="$(curl -sSL -D - -o /dev/null --max-time 20 "$URL" 2>/dev/null || true)"
  if [ -z "$hdrs" ]; then bad "could not reach $URL"; line "- could not reach target"; else
    checkhdr() { # name  regex  severity
      if printf '%s' "$hdrs" | grep -iq "$2"; then ok "$1 present"; else bad "$1 MISSING"; add "$3"; line "- **$(echo "$3"|tr a-z A-Z)** missing header: $1"; fi; }
    checkhdr "Strict-Transport-Security" "^strict-transport-security:" med
    if printf '%s' "$hdrs" | grep -iq "^content-security-policy:"; then ok "Content-Security-Policy present (enforcing)";
    elif printf '%s' "$hdrs" | grep -iq "^content-security-policy-report-only:"; then warn "Content-Security-Policy is Report-Only (tune, then enforce)"; add low; line "- **LOW** CSP present but Report-Only — promote to enforcing after tuning";
    else bad "Content-Security-Policy MISSING"; add med; line "- **MEDIUM** missing header: Content-Security-Policy"; fi
    checkhdr "X-Content-Type-Options"     "^x-content-type-options:" low
    checkhdr "X-Frame-Options / frame-ancestors" "^x-frame-options:\|frame-ancestors" low
    checkhdr "Referrer-Policy"            "^referrer-policy:" low
    checkhdr "Permissions-Policy"         "^permissions-policy:" low
    printf '%s' "$hdrs" | grep -iq "^access-control-allow-origin: \*" && { warn "CORS: wildcard Access-Control-Allow-Origin"; add med; line "- **MEDIUM** CORS wildcard (Access-Control-Allow-Origin: *)"; } || ok "no wildcard CORS on this response"
    printf '%s' "$hdrs" | grep -iq "^set-cookie:" && { printf '%s' "$hdrs" | grep -i "^set-cookie:" | grep -iq "httponly" && ok "cookies: HttpOnly seen" || { warn "cookie without HttpOnly"; add med; line "- **MEDIUM** Set-Cookie without HttpOnly"; }; }
    printf '%s' "$hdrs" | grep -iqE "^server: .*(apache|nginx|express)/[0-9]" && { warn "Server banner leaks version"; add low; line "- **LOW** Server header leaks software version"; }
    if have openssl && printf '%s' "$URL" | grep -q '^https'; then
      hostp="${URL#https://}"; hostp="${hostp%%/*}"; host="${hostp%%:*}"; port="${hostp##*:}"; [ "$port" = "$host" ] && port=443
      proto=$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | grep -i "Protocol" | head -1)
      echo "$proto" | grep -qiE "TLSv1\.[01]" && { bad "TLS: legacy protocol negotiated ($proto)"; add high; line "- **HIGH** legacy TLS protocol negotiated"; } || ok "TLS: modern protocol"
    fi
  fi
else
  head2 "5. Dynamic checks"; skip "dynamic checks" "pass --url https://your.app to enable"
fi

# ── summary + gate ──
TOTAL=$((CRIT+HIGH+MED+LOW))
head2 "Summary"
printf '  %sCRITICAL %s  %sHIGH %s  %sMEDIUM %s  %sLOW %s  (total %s)\n' \
  "$C_R" "$CRIT" "$C_R" "$HIGH" "$C_Y" "$MED" "$C_D" "$LOW" "$TOTAL"
{ echo; echo "## Summary"; echo;
  echo "| Severity | Count |"; echo "|---|---|";
  echo "| Critical | $CRIT |"; echo "| High | $HIGH |"; echo "| Medium | $MED |"; echo "| Low | $LOW |";
  echo; echo "_Full tool output in \`$OUTDIR/\`. Triage before acting — scanners produce false positives._"; } >> "$REPORT"
say "  report: $C_BOLD$REPORT$C_0"

gate=0
case "$FAIL_ON" in
  never) gate=0;;
  any)      [ "$TOTAL" -gt 0 ] && gate=1;;
  low)      [ $((CRIT+HIGH+MED+LOW)) -gt 0 ] && gate=1;;
  medium)   [ $((CRIT+HIGH+MED)) -gt 0 ] && gate=1;;
  high)     [ $((CRIT+HIGH)) -gt 0 ] && gate=1;;
  critical) [ "$CRIT" -gt 0 ] && gate=1;;
esac
if [ "$gate" = 1 ]; then bad "FAIL — findings at/above '$FAIL_ON' threshold"; exit 1; fi
ok "PASS — no findings above '$FAIL_ON' threshold"; exit 0
