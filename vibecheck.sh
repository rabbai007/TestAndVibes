#!/usr/bin/env bash
#
# VibeCheck — portable, non-destructive security audit for web apps.
#
#   Static analysis:  secrets · SAST · dependency CVEs · IaC/container misconfig
#   Dynamic (opt-in): HTTP security headers · TLS · cookie flags  (your URL only)
#
# Wraps best-in-class OSS scanners (semgrep, trivy, grype, trufflehog, gitleaks,
# npm audit) behind one command, auto-detects the stack, and emits a
# consolidated report, a SARIF file, and a CI-friendly exit code.
#
# FAILS CLOSED: a pass that cannot complete (missing lockfile, crashed scanner,
# unreachable URL) is reported as ERROR and exits 3 — never as "clean". A
# security gate must distinguish "nothing found" from "nothing looked".
#
# LEGAL: run only against code and systems you own or are explicitly authorized
# to test. The dynamic checks are read-only (a GET + TLS handshake) — no
# exploitation, no payloads. You are responsible for how you use this.
#
# Requires: bash, jq. Scanners are optional but a missing one is an ERROR
# unless you explicitly skip that pass (see --skip-* / vibecheck.yml).
set -uo pipefail

VERSION="0.3.1"
TOOL_URL="https://github.com/rabbai007/TestAndVibes"

# ── defaults (overridable by vibecheck.yml, then CLI flags) ──
TARGET="."
URL=""
DYNAMIC=0
FAIL_ON="high"          # never | low | medium | high | critical | any
FAIL_ON_ERROR=1         # 1 = a pass that cannot run exits 3 (fail closed)
OUTDIR="vibecheck-report"
CONFIG=""
SELF_INSTALL=0
SEMGREP_CONFIG="auto"
SECRETS_STRICT=0        # 1 = unverified secrets count as high, not medium
DO_SECRETS=1; DO_SAST=1; DO_DEPS=1; DO_IAC=1
DO_PDF=0                # 1 = also render report.pdf (needs Chrome/wkhtmltopdf/weasyprint)
DO_OPEN=0               # 1 = open the HTML report in the default browser
DIFF_REF=""             # gate only on findings in files changed vs this git ref
BASELINE=""             # path to an accepted-findings baseline
USE_BASELINE=1          # 0 = ignore any baseline file that exists
WRITE_BASELINE=0        # 1 = merge current findings into the baseline and exit
BASELINE_STALE_DAYS=90  # warn about accepted entries older than this

# ── pretty output ──
if [ -t 1 ]; then C_R=$'\033[31m'; C_Y=$'\033[33m'; C_G=$'\033[32m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'; C_BOLD=$'\033[1m'
else C_R=; C_Y=; C_G=; C_B=; C_D=; C_0=; C_BOLD=; fi
say()  { printf '%s\n' "$*"; }
head2(){ printf '\n%s▶ %s%s\n' "$C_B$C_BOLD" "$*" "$C_0"; }
ok()   { printf '  %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$C_R" "$C_0" "$*"; }
err()  { printf '  %s⨯ ERROR: %s%s\n' "$C_R$C_BOLD" "$*" "$C_0"; }
skip() { printf '  %s— %s (skipped: %s)%s\n' "$C_D" "$1" "$2" "$C_0"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
VibeCheck v$VERSION — portable, non-destructive security audit for web apps.

USAGE
  vibecheck.sh [options]

OPTIONS
  --dir PATH           Directory to scan (default: .)
  --url URL            Enable read-only dynamic checks against URL (implies --dynamic)
  --dynamic            Enable dynamic checks (requires --url)
  --all                Static + dynamic
  --fail-on LEVEL      Gate threshold: never|low|medium|high|critical|any (default: high)
  --no-fail-on-error   Do NOT exit 3 when a pass cannot complete (unsafe; opts out
                       of fail-closed behavior)
  --out DIR            Report directory (default: vibecheck-report)
  --config PATH        Config file (default: ./vibecheck.yml if present)
  --semgrep-config X   Semgrep ruleset (default: auto; use p/ci for offline-safe)
  --secrets-strict     Treat unverified secrets as high severity (default: medium)
  --skip-secrets       Skip the secret pass (not an ERROR)
  --skip-sast          Skip the SAST pass
  --skip-deps          Skip the dependency pass
  --skip-iac           Skip the IaC pass
  --pdf                Also render DIR/report.pdf (Chrome, wkhtmltopdf, or weasyprint)
  --open               Open the HTML report in your default browser when done
  --diff REF           PR mode: gate only on findings in files changed vs REF
                       (e.g. --diff origin/main). Findings elsewhere are still
                       reported. Run a full scan on your default branch too.
  --baseline PATH      Accepted-findings file (default: ./.vibecheck-baseline.json)
  --write-baseline     Accept every current finding into the baseline, then exit
  --no-baseline        Ignore any baseline file and gate on everything
  --install            Install the underlying scanners and exit
  --version            Print version and exit
  -h, --help           This help

OUTPUT
  DIR/report.md        Consolidated findings + per-pass status
  DIR/report.html      Formatted, self-contained report (print/PDF-ready)
  DIR/report.pdf       Same report as PDF (with --pdf)
  DIR/vibecheck.sarif  SARIF 2.1.0 (GitHub Code Scanning / any SARIF viewer)
  DIR/findings.json    Machine-readable findings
  DIR/*.json           Raw per-scanner output for triage

EXIT CODES
  0  clean at/under threshold
  1  findings at/above threshold
  2  usage or internal error
  3  a pass could not complete (fail-closed; see --no-fail-on-error)

LEGAL: only scan code and systems you own or are authorized to test.
EOF
  exit 0
}

# ── config file (fixed key subset, not general YAML) ──
# Reads only the keys documented in config/vibecheck.example.yml. CLI flags win.
cfg_get() { # file  dotted.key  -> value on stdout (empty if absent)
  local f="$1" k="$2"
  case "$k" in
    *.*) # one level of nesting: parent then indented child
      local parent="${k%%.*}" child="${k#*.}"
      awk -v p="^${parent}:" -v c="^[[:space:]]+${child}:" '
        $0 ~ p {inb=1; next}
        inb && /^[^[:space:]#]/ {inb=0}
        inb && $0 ~ c {sub(c, ""); print; exit}' "$f" |
        sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//'
      ;;
    *)
      awk -v k="^${k}:" '$0 ~ k {sub(k, ""); print; exit}' "$f" |
        sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; s/^["'\'']//; s/["'\'']$//'
      ;;
  esac
}
load_config() {
  local f="$1" v
  [ -f "$f" ] || return 0
  v="$(cfg_get "$f" fail_on)";              [ -n "$v" ] && FAIL_ON="$v"
  v="$(cfg_get "$f" out)";                  [ -n "$v" ] && OUTDIR="$v"
  v="$(cfg_get "$f" dynamic.url)";          [ -n "$v" ] && { URL="$v"; DYNAMIC=1; }
  v="$(cfg_get "$f" scanners.secrets)";     [ "$v" = "false" ] && DO_SECRETS=0
  v="$(cfg_get "$f" scanners.sast)";        [ "$v" = "false" ] && DO_SAST=0
  v="$(cfg_get "$f" scanners.dependencies)";[ "$v" = "false" ] && DO_DEPS=0
  v="$(cfg_get "$f" scanners.iac)";         [ "$v" = "false" ] && DO_IAC=0
  v="$(cfg_get "$f" fail_on_error)";        [ "$v" = "false" ] && FAIL_ON_ERROR=0
  CONFIG_USED="$f"
}

# ── args (parsed twice: --config first so flags can override the file) ──
CONFIG_USED=""
_args=("$@")
for ((i=0; i<${#_args[@]}; i++)); do
  [ "${_args[$i]}" = "--config" ] && CONFIG="${_args[$((i+1))]:-}"
done
if [ -n "$CONFIG" ]; then
  [ -f "$CONFIG" ] || { err "config not found: $CONFIG"; exit 2; }
  load_config "$CONFIG"
elif [ -f "./vibecheck.yml" ]; then
  load_config "./vibecheck.yml"
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) TARGET="${2:?--dir needs a path}"; shift 2;;
    --url) URL="${2:?--url needs a URL}"; DYNAMIC=1; shift 2;;
    --dynamic) DYNAMIC=1; shift;;
    --all) DYNAMIC=1; shift;;
    --fail-on) FAIL_ON="${2:?--fail-on needs a level}"; shift 2;;
    --no-fail-on-error) FAIL_ON_ERROR=0; shift;;
    --out) OUTDIR="${2:?--out needs a path}"; shift 2;;
    --config) shift 2;;                       # already handled above
    --semgrep-config) SEMGREP_CONFIG="${2:?}"; shift 2;;
    --secrets-strict) SECRETS_STRICT=1; shift;;
    --skip-secrets) DO_SECRETS=0; shift;;
    --skip-sast) DO_SAST=0; shift;;
    --skip-deps) DO_DEPS=0; shift;;
    --skip-iac) DO_IAC=0; shift;;
    --pdf) DO_PDF=1; shift;;
    --open) DO_OPEN=1; shift;;
    --diff) DIFF_REF="${2:?--diff needs a git ref}"; shift 2;;
    --baseline) BASELINE="${2:?--baseline needs a path}"; shift 2;;
    --write-baseline) WRITE_BASELINE=1; shift;;
    --no-baseline) USE_BASELINE=0; shift;;
    --install) SELF_INSTALL=1; shift;;
    --version) say "VibeCheck v$VERSION"; exit 0;;
    -h|--help) usage;;
    *) err "unknown arg: $1  (try --help)"; exit 2;;
  esac
done

# validate the gate threshold — an unrecognized value used to silently pass
case "$FAIL_ON" in
  never|low|medium|high|critical|any) ;;
  *) err "invalid --fail-on '$FAIL_ON' (expected: never|low|medium|high|critical|any)"; exit 2;;
esac

# ── self-install ──
if [ "$SELF_INSTALL" = 1 ]; then
  head2 "Installing scanners"
  if have brew; then
    brew install jq trivy grype trufflehog gitleaks 2>/dev/null || true
  else
    say "  Homebrew not found. Install manually:"
    say "    jq        : https://jqlang.github.io/jq/download/   (REQUIRED)"
    say "    trivy     : https://trivy.dev"
    say "    grype     : https://github.com/anchore/grype#installation"
    say "    trufflehog: https://github.com/trufflesecurity/trufflehog#installation"
    say "    gitleaks  : https://github.com/gitleaks/gitleaks#installing"
  fi
  if have pipx; then pipx install semgrep 2>/dev/null || true
  elif have pip3; then pip3 install --user semgrep 2>/dev/null || true
  else say "    semgrep   : pipx install semgrep  (https://semgrep.dev)"; fi
  ok "install pass complete (re-run without --install to scan)"
  exit 0
fi

# jq is a hard dependency: correct JSON parsing is the whole point of 0.2.0
have jq || { err "jq is required (brew install jq | apt-get install -y jq)"; exit 2; }

[ -d "$TARGET" ] || { err "target dir not found: $TARGET"; exit 2; }
TARGET="$(cd "$TARGET" && pwd)"
mkdir -p "$OUTDIR" || { err "cannot create out dir: $OUTDIR"; exit 2; }
OUTDIR="$(cd "$OUTDIR" && pwd)"
REPORT="$OUTDIR/report.md"
HTML="$OUTDIR/report.html"
PDF="$OUTDIR/report.pdf"
FINDINGS="$OUTDIR/.findings.jsonl"
ACTIVE="$OUTDIR/.active.jsonl"      # findings that count toward the gate
ACCEPTED="$OUTDIR/.accepted.jsonl"  # findings suppressed by the baseline
STATUS="$OUTDIR/.status.jsonl"
SARIF="$OUTDIR/vibecheck.sarif"
: > "$FINDINGS"; : > "$STATUS"; : > "$ACTIVE"; : > "$ACCEPTED"

# ── fingerprinting ──
# Identity for baselining is tool|rule|file|title — deliberately NOT the line
# number, which shifts whenever anything above the finding is edited and would
# make every accepted entry reappear on the next commit. The title is included
# so two hits of the same rule in one file stay distinct.
sha12() {
  if have shasum;    then shasum -a 256 2>/dev/null | cut -c1-12
  elif have sha256sum; then sha256sum 2>/dev/null | cut -c1-12
  elif have openssl; then openssl dgst -sha256 2>/dev/null | sed 's/.*= *//' | cut -c1-12
  else cksum | tr -d ' ' | cut -c1-12   # stability is what matters, not strength
  fi
}
fingerprint() { printf '%s|%s|%s|%s' "$1" "$2" "$3" "$4" | sha12; }

# ── findings + status stores (single source of truth for every output) ──
# add_finding  tool severity rule file line title [helpUri]
add_finding() {
  local fp; fp="$(fingerprint "$1" "$3" "$4" "$6")"
  jq -cn --arg tool "$1" --arg sev "$2" --arg rule "$3" --arg file "$4" \
         --arg line "${5:-0}" --arg title "$6" --arg help "${7:-}" --arg fp "$fp" \
    '{tool:$tool, severity:$sev, rule:$rule, file:$file,
      line:(($line|tonumber?)//0), title:$title, help:$help, fingerprint:$fp}' >> "$FINDINGS"
}
# set_status  pass  ok|findings|skipped|error  detail
set_status() {
  jq -cn --arg p "$1" --arg s "$2" --arg d "${3:-}" \
    '{pass:$p, status:$s, detail:$d}' >> "$STATUS"
}
# pass_error  pass  message   → records ERROR (drives fail-closed exit 3)
pass_error() { err "$2"; set_status "$1" error "$2"; }

sev_count() { jq -s --arg s "$1" '[.[]|select(.severity==$s)]|length' "$ACTIVE"; }
rel() { printf '%s' "${1#$TARGET/}"; }

# ── baseline (accepted findings) ──
# Resolve after TARGET is known so a repo-local baseline is picked up.
if [ "$USE_BASELINE" = 1 ] && [ -z "$BASELINE" ]; then
  for c in "$TARGET/.vibecheck-baseline.json" "./.vibecheck-baseline.json"; do
    [ -f "$c" ] && { BASELINE="$c"; break; }
  done
fi
if [ -n "$BASELINE" ] && [ "$USE_BASELINE" = 1 ]; then
  if [ ! -f "$BASELINE" ]; then
    [ "$WRITE_BASELINE" = 1 ] || { err "baseline not found: $BASELINE"; exit 2; }
  elif ! jq -e '.entries' "$BASELINE" >/dev/null 2>&1; then
    err "baseline is not valid VibeCheck baseline JSON: $BASELINE"; exit 2
  fi
fi
# days since a YYYY-MM-DD date (portable across GNU/BSD date); empty if unparseable
days_since() {
  local d="$1" e
  e="$(date -j -f '%Y-%m-%d' "$d" +%s 2>/dev/null || date -d "$d" +%s 2>/dev/null || echo '')"
  [ -n "$e" ] && echo $(( ( $(date +%s) - e ) / 86400 )) || echo ''
}

# ── exclusions (.vibecheckignore, else sane defaults) ──
IGNORE_FILE=""
for c in "$TARGET/.vibecheckignore" "./.vibecheckignore"; do
  [ -f "$c" ] && { IGNORE_FILE="$c"; break; }
done
EXCLUDES=()
if [ -n "$IGNORE_FILE" ]; then
  while IFS= read -r pat; do
    case "$pat" in ''|'#'*) continue;; esac
    EXCLUDES+=("${pat%/}")
  done < "$IGNORE_FILE"
else
  EXCLUDES=(node_modules dist build vendor .git coverage .venv target)
fi
# regex file for trufflehog --exclude-paths
TH_EXCLUDE="$OUTDIR/.th-exclude"
: > "$TH_EXCLUDE"
for e in "${EXCLUDES[@]}"; do printf '%s\n' "$e" >> "$TH_EXCLUDE"; done

STAMP="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo now)"
say "${C_BOLD}VibeCheck v$VERSION${C_0}  —  $TARGET"
[ -n "$CONFIG_USED" ] && say "  ${C_D}config: $CONFIG_USED${C_0}"
[ -n "$IGNORE_FILE" ] && say "  ${C_D}ignore: $IGNORE_FILE${C_0}"

# ── stack detection ──
head2 "Stack detection"
STACK=""
det() { [ -e "$TARGET/$1" ] && { case " $STACK " in *" $2 "*) :;; *) STACK="$STACK $2"; ok "$2 ($1)";; esac; }; }
det package.json node
det requirements.txt python; det pyproject.toml python; det Pipfile python
det go.mod go
det Cargo.toml rust
det composer.json php
det Gemfile ruby
det pom.xml java; det build.gradle java; det build.gradle.kts java
det mix.exs elixir
det Dockerfile docker
det docker-compose.yml docker-compose; det docker-compose.yaml docker-compose
det Chart.yaml helm

# find nested markers the 0.1.0 top-level globs missed
PRUNE=(); for e in "${EXCLUDES[@]}"; do PRUNE+=(-name "$e" -prune -o); done
findx() { find "$TARGET" "${PRUNE[@]}" -type f "$@" -print 2>/dev/null; }

[ -n "$(findx -name '*.tf' | head -1)" ]        && { STACK="$STACK terraform"; ok "terraform (*.tf, recursive)"; }
[ -n "$(findx -name '*.csproj' -o -name '*.fsproj' | head -1)" ] && { STACK="$STACK dotnet"; ok "dotnet (*.csproj)"; }
[ -n "$(findx -name '*.gradle' -o -name '*.gradle.kts' | head -1)" ] && \
  { case " $STACK " in *" java "*) :;; *) STACK="$STACK java"; ok "java (gradle, recursive)";; esac; }
[ -d "$TARGET/.git" ] && { STACK="$STACK git"; ok "git repo"; }
[ -z "${STACK// /}" ] && warn "no known stack markers found — running generic checks"

has_stack() { case " $STACK " in *" $1 "*) return 0;; *) return 1;; esac; }

# ═══════════════════════════════════════════════════════════════════
# 1. secret scanning
# ═══════════════════════════════════════════════════════════════════
head2 "1. Secret scanning"
if [ "$DO_SECRETS" = 0 ]; then
  skip "secret scan" "--skip-secrets"; set_status secrets skipped "--skip-secrets"
elif have trufflehog; then
  # One pass, both verdicts. 0.1.0 used --only-verified, which silently dropped
  # every secret trufflehog cannot authenticate live (DB passwords, private
  # keys, internal tokens). We classify per finding instead.
  UNSEV=medium; [ "$SECRETS_STRICT" = 1 ] && UNSEV=high
  th_json="$OUTDIR/trufflehog.json"; : > "$th_json"
  th_failed=0
  if [ -d "$TARGET/.git" ]; then
    trufflehog git "file://$TARGET" --json --no-update >> "$th_json" 2>/dev/null || th_failed=$((th_failed+1))
  fi
  trufflehog filesystem "$TARGET" --json --no-update \
    --exclude-paths "$TH_EXCLUDE" >> "$th_json" 2>/dev/null || th_failed=$((th_failed+1))

  # trufflehog exits non-zero when it finds secrets, so a non-zero exit alone
  # is not an error — only unparseable output is.
  if ! jq -e -rR 'fromjson? | .DetectorName? // empty' "$th_json" >/dev/null 2>&1 && [ -s "$th_json" ]; then
    pass_error secrets "trufflehog produced unparseable output — see $th_json"
  else
    nv=0; nu=0
    while IFS=$'\t' read -r verified detector file lineno raw; do
      [ -z "${detector:-}" ] && continue
      f="$(rel "${file:-}")"
      if [ "$verified" = "true" ]; then
        nv=$((nv+1)); add_finding trufflehog critical "verified-secret.$detector" \
          "$f" "${lineno:-0}" "Verified live $detector credential in $([ -n "$f" ] && echo "$f" || echo 'git history')" \
          "https://trufflesecurity.com/blog/verified-secrets"
      else
        nu=$((nu+1)); add_finding trufflehog "$UNSEV" "unverified-secret.$detector" \
          "$f" "${lineno:-0}" "Possible $detector credential (unverified — confirm manually)" ""
      fi
    done < <(jq -rR 'fromjson? | select(.DetectorName)
                     | [ (.Verified|tostring), .DetectorName,
                         (.SourceMetadata.Data.Filesystem.file // .SourceMetadata.Data.Git.file // ""),
                         ((.SourceMetadata.Data.Filesystem.line // .SourceMetadata.Data.Git.line // 0)|tostring)
                       ] | @tsv' "$th_json" 2>/dev/null | sort -u)

    [ "$nv" -gt 0 ] && bad "trufflehog: $nv VERIFIED secret(s) — rotate these now" || ok "trufflehog: 0 verified secrets"
    [ "$nu" -gt 0 ] && warn "trufflehog: $nu unverified candidate(s) ($UNSEV) — triage" || ok "trufflehog: 0 unverified candidates"
    if [ $((nv+nu)) -gt 0 ]; then set_status secrets findings "$nv verified, $nu unverified"; else set_status secrets ok "0 secrets"; fi
  fi
elif have gitleaks; then
  gl="$OUTDIR/gitleaks.json"; glh="$OUTDIR/.gitleaks-history.json"
  rm -f "$gl" "$glh"
  # gitleaks exit codes: 0 = clean, 1 = leaks found, >1 = the scan itself failed.
  # (0.1.0 treated ANY non-zero exit as "secrets found", including "not a git repo".)
  #
  # `detect` is deprecated in gitleaks 8.19+ in favour of the `git` and `dir`
  # subcommands, and `--no-git` goes with it. Probe for the modern CLI and fall
  # back, so both old and new installs work.
  gl_modern=0
  gitleaks dir --help >/dev/null 2>&1 && gl_modern=1
  gl_fail=0; gl_files=""
  gl_run() { # report-file  args...
    local out="$1"; shift
    gitleaks "$@" --no-banner --report-format json -r "$out" >/dev/null 2>&1
    local rc=$?
    [ "$rc" -gt 1 ] && { gl_fail=$rc; return 1; }
    [ -f "$out" ] && gl_files="$gl_files $out"
    return 0
  }
  # Scan history AND the working tree, matching the trufflehog path. Previously
  # only history was scanned on a git repo, so an uncommitted secret — the exact
  # thing a pre-commit check should catch — was invisible.
  if [ "$gl_modern" = 1 ]; then
    [ -d "$TARGET/.git" ] && gl_run "$glh" git "$TARGET"
    gl_run "$gl" dir "$TARGET"
  else
    if [ -d "$TARGET/.git" ]; then gl_run "$glh" detect --source "$TARGET"
                                   gl_run "$gl" detect --source "$TARGET" --no-git
    else gl_run "$gl" detect --source "$TARGET" --no-git; fi
  fi

  if [ "$gl_fail" -gt 1 ]; then
    pass_error secrets "gitleaks exited $gl_fail (scan did not complete)"
  elif [ -z "${gl_files// /}" ]; then
    pass_error secrets "gitleaks produced no parseable report"
  else
    for f in $gl_files; do
      jq -e . "$f" >/dev/null 2>&1 || { pass_error secrets "gitleaks wrote unparseable JSON to $f"; gl_fail=99; break; }
    done
    if [ "$gl_fail" != 99 ]; then
      n=0
      while IFS=$'\t' read -r ruleid file lineno desc; do
        [ -z "${ruleid:-}" ] && continue
        n=$((n+1)); add_finding gitleaks high "gitleaks.$ruleid" "$(rel "$file")" "$lineno" "${desc:-Secret detected}" ""
      # `gitleaks git` reports repo-relative paths while `gitleaks dir` reports
      # absolute ones, so normalise BEFORE dedup or the same secret is counted
      # twice — once from history, once from the working tree.
      done < <(jq -r -s --arg t "$TARGET/" 'add // [] | .[]?
                  | [(.RuleID//"unknown"), ((.File//"")|ltrimstr($t)), ((.StartLine//0)|tostring),
                     ((.Description//"")|gsub("[\n\t]";" "))] | @tsv' \
                  $gl_files 2>/dev/null | sort -u)
      [ "$n" -gt 0 ] && { bad "gitleaks: $n potential secret(s)"; set_status secrets findings "$n"; } \
                     || { ok "gitleaks: no secrets"; set_status secrets ok "0 secrets"; }
    fi
  fi
else
  pass_error secrets "no secret scanner installed (trufflehog or gitleaks) — cannot verify absence of secrets"
fi

# ═══════════════════════════════════════════════════════════════════
# 2. SAST
# ═══════════════════════════════════════════════════════════════════
head2 "2. Static analysis (SAST)"
if [ "$DO_SAST" = 0 ]; then
  skip "SAST" "--skip-sast"; set_status sast skipped "--skip-sast"
elif have semgrep; then
  sg="$OUTDIR/semgrep.json"; rm -f "$sg"
  sg_args=(scan "--config=$SEMGREP_CONFIG" --json "--output=$sg" --quiet --disable-version-check)
  for e in "${EXCLUDES[@]}"; do sg_args+=("--exclude=$e"); done
  semgrep "${sg_args[@]}" "$TARGET" >/dev/null 2>"$OUTDIR/.semgrep.err"; sg_rc=$?
  # semgrep: 0 = no findings, 1 = findings, >1 = error. A crashed/offline
  # semgrep used to look identical to a clean scan.
  if [ ! -f "$sg" ] || ! jq -e . "$sg" >/dev/null 2>&1; then
    pass_error sast "semgrep exited $sg_rc and produced no parseable JSON — $(head -c 200 "$OUTDIR/.semgrep.err" 2>/dev/null | tr '\n' ' ')"
  else
    # semgrep records rule-level errors (e.g. registry unreachable) in .errors
    sg_errs=$(jq '[.errors[]?|select((.level//"")=="error")]|length' "$sg" 2>/dev/null || echo 0)
    e=0; w=0; i=0
    while IFS=$'\t' read -r sev rule file lineno msg url; do
      [ -z "${rule:-}" ] && continue
      case "$sev" in
        ERROR)   vs=high;   e=$((e+1));;
        WARNING) vs=medium; w=$((w+1));;
        *)       vs=low;    i=$((i+1));;
      esac
      add_finding semgrep "$vs" "$rule" "$(rel "$file")" "$lineno" "$msg" "$url"
    done < <(jq -r '.results[]? | [ (.extra.severity//"INFO"), (.check_id//"semgrep"),
                                    (.path//""), ((.start.line//0)|tostring),
                                    ((.extra.message//"finding")|gsub("[\n\t]";" ")),
                                    (.extra.metadata.shortlink // (.extra.metadata.references//[])[0] // "")
                                  ] | @tsv' "$sg" 2>/dev/null)
    [ "$e" -gt 0 ] && bad "semgrep: $e error-level finding(s)"    || ok "semgrep: 0 error-level findings"
    [ "$w" -gt 0 ] && warn "semgrep: $w warning-level finding(s)"
    [ "$i" -gt 0 ] && say  "  ${C_D}semgrep: $i info-level finding(s)${C_0}"
    if [ "${sg_errs:-0}" -gt 0 ]; then
      pass_error sast "semgrep reported $sg_errs internal rule error(s) — coverage incomplete (see $sg)"
    elif [ $((e+w+i)) -gt 0 ]; then set_status sast findings "$e error, $w warning, $i info"
    else set_status sast ok "0 findings"; fi
  fi
else
  pass_error sast "semgrep not installed — cannot run SAST (pipx install semgrep, or --skip-sast)"
fi

# ═══════════════════════════════════════════════════════════════════
# 3. dependency CVEs
# ═══════════════════════════════════════════════════════════════════
head2 "3. Dependency vulnerabilities"
# Lockfile presence is a precondition, not a detail: trivy silently returns an
# empty report for a manifest with no lockfile, which 0.1.0 rendered as "clean".
LOCK_OK=0; LOCK_MISSING=""
lockcheck() { # stack  "file1 file2 ..."
  has_stack "$1" || return 0
  local f
  for f in $2; do
    [ -n "$(findx -name "$f" | head -1)" ] && { LOCK_OK=1; return 0; }
  done
  LOCK_MISSING="$LOCK_MISSING $1"
}
lockcheck node   "package-lock.json yarn.lock pnpm-lock.yaml npm-shrinkwrap.json bun.lockb"
lockcheck python "poetry.lock Pipfile.lock uv.lock requirements.txt"
lockcheck go     "go.sum"
lockcheck rust   "Cargo.lock"
lockcheck php    "composer.lock"
lockcheck ruby   "Gemfile.lock"
lockcheck java   "pom.xml gradle.lockfile"
lockcheck dotnet "packages.lock.json"

DEP_ANY=0
DEPS_ERRORED=0
deps_error() { DEPS_ERRORED=1; pass_error deps "$1"; }
# trivy logs parser failures to stderr and still reports "0 findings" — a syntax
# error in a lockfile or .tf must not read as clean.
trivy_parse_errors() { # errfile -> prints offending lines, returns 0 if any
  [ -f "$1" ] || return 1
  grep -E 'ERROR.*(parser|Error parsing|failed to parse)' "$1" 2>/dev/null | head -3
}

# A repo with no dependency manifest at all has nothing to scan — that is a
# legitimate skip, not an incomplete scan. Only stacks that actually carry
# dependencies make the deps pass mandatory.
DEP_STACK=0
for s in node python go rust php ruby java dotnet elixir; do has_stack "$s" && DEP_STACK=1; done

if [ "$DO_DEPS" = 0 ]; then
  skip "dependency scan" "--skip-deps"; set_status deps skipped "--skip-deps"
elif [ "$DEP_STACK" = 0 ]; then
  skip "dependency scan" "no dependency manifests found"; set_status deps skipped "no manifests"
else
  dep_add() { # tool severity id target pkg title url
    add_finding "$1" "$2" "$3" "$4" 0 "$5" "${6:-}"
  }
  scanned=0
  # "a scanner was present but failed" must not fall through to a weaker tool
  # and re-report the same problem twice.
  dep_tool_present=0
  { have trivy || have grype; } && dep_tool_present=1
  if have trivy; then
    tv="$OUTDIR/trivy-deps.json"; rm -f "$tv"
    tv_args=(fs --scanners vuln --severity MEDIUM,HIGH,CRITICAL --quiet --format json --output "$tv")
    for e in "${EXCLUDES[@]}"; do tv_args+=(--skip-dirs "$e"); done
    trivy "${tv_args[@]}" "$TARGET" >/dev/null 2>"$OUTDIR/.trivy.err"; tv_rc=$?
    if [ ! -f "$tv" ] || ! jq -e . "$tv" >/dev/null 2>&1; then
      deps_error "trivy exited $tv_rc and produced no parseable JSON — $(head -c 200 "$OUTDIR/.trivy.err" 2>/dev/null | tr '\n' ' ')"
    elif ! jq -e 'has("Results")' "$tv" >/dev/null 2>&1; then
      # THE 0.1.0 false-clean: no Results key means trivy found nothing it could
      # parse — not that the dependencies are clean.
      if [ -n "${LOCK_MISSING// /}" ]; then
        deps_error "no scannable lockfile for:${LOCK_MISSING} — commit a lockfile (npm i --package-lock-only) or --skip-deps. Dependencies NOT scanned."
      else
        deps_error "trivy returned no results for a detected stack ($(echo "$STACK" | tr -s ' ')) — dependencies were NOT scanned"
      fi
    elif pe="$(trivy_parse_errors "$OUTDIR/.trivy.err")" && [ -n "$pe" ]; then
      deps_error "trivy could not parse one or more manifests (results incomplete): $(printf '%s' "$pe" | tr '\n' ' ' | head -c 200)"
    else
      c=0; h=0; m=0
      while IFS=$'\t' read -r sev cve target pkg title url; do
        [ -z "${cve:-}" ] && continue
        case "$sev" in
          CRITICAL) c=$((c+1)); vs=critical;;
          HIGH)     h=$((h+1)); vs=high;;
          *)        m=$((m+1)); vs=medium;;
        esac
        dep_add trivy "$vs" "$cve" "$(rel "$target")" "$pkg: $title" "$url"
      done < <(jq -r '.Results[]? | .Target as $t | (.Vulnerabilities//[])[]
                      | [ .Severity, .VulnerabilityID, $t,
                          (.PkgName + "@" + (.InstalledVersion//"?")),
                          ((.Title // .Description // "known vulnerability")|gsub("[\n\t]";" ")|.[0:160]),
                          (.PrimaryURL//"")
                        ] | @tsv' "$tv" 2>/dev/null |
                  sort -u -t$'\t' -k2,2 -k4,4)   # dedup: same CVE + same pkg version
      [ "$c" -gt 0 ] && bad  "trivy: $c CRITICAL dependency CVE(s)"
      [ "$h" -gt 0 ] && warn "trivy: $h HIGH dependency CVE(s)"
      [ "$m" -gt 0 ] && say  "  ${C_D}trivy: $m MEDIUM dependency CVE(s)${C_0}"
      [ $((c+h+m)) -eq 0 ] && ok "trivy: 0 MEDIUM+ dependency CVEs"
      DEP_ANY=$((c+h+m)); scanned=1
    fi
  elif have grype; then
    # grype was advertised in 0.1.0's README and installed by --install, but
    # never actually invoked. It is now the real fallback.
    gr="$OUTDIR/grype.json"; rm -f "$gr"
    grype "dir:$TARGET" -o json --file "$gr" >/dev/null 2>&1; gr_rc=$?
    if [ ! -f "$gr" ] || ! jq -e . "$gr" >/dev/null 2>&1; then
      deps_error "grype exited $gr_rc and produced no parseable JSON"
    else
      n=0
      while IFS=$'\t' read -r sev cve pkg url; do
        [ -z "${cve:-}" ] && continue
        case "$sev" in
          Critical) vs=critical;; High) vs=high;; Medium) vs=medium;; *) vs=low;;
        esac
        n=$((n+1)); dep_add grype "$vs" "$cve" "dependencies" "$pkg" "$url"
      done < <(jq -r '.matches[]? | [ (.vulnerability.severity//"Unknown"),
                        (.vulnerability.id//""), (.artifact.name+"@"+(.artifact.version//"?")),
                        (.vulnerability.dataSource//"") ] | @tsv' "$gr" 2>/dev/null | sort -u)
      [ "$n" -gt 0 ] && warn "grype: $n vulnerability match(es)" || ok "grype: 0 vulnerabilities"
      DEP_ANY=$n; scanned=1
    fi
  fi

  # npm audit is a supplement, not a substitute — it only covers the node tree.
  # Only used when no real scanner is installed; if trivy/grype ran and failed,
  # that failure is already recorded and must not be reported twice.
  if [ "$scanned" = 0 ] && [ "$dep_tool_present" = 0 ] && has_stack node && have npm; then
    if [ -n "$(findx -name 'package-lock.json' | head -1)" ]; then
      na="$OUTDIR/npm-audit.json"
      (cd "$TARGET" && npm audit --omit=dev --json > "$na" 2>/dev/null) || true
      if [ -f "$na" ] && jq -e . "$na" >/dev/null 2>&1; then
        n=0
        while IFS=$'\t' read -r sev pkg title url; do
          [ -z "${pkg:-}" ] && continue
          case "$sev" in critical) vs=critical;; high) vs=high;; moderate) vs=medium;; *) vs=low;; esac
          n=$((n+1)); dep_add "npm-audit" "$vs" "npm.$pkg" "package-lock.json" "$pkg: $title" "$url"
        done < <(jq -r '.vulnerabilities // {} | to_entries[] | .value
                        | [ (.severity//"low"), (.name//""),
                            (((.via//[])|map(if type=="object" then .title else . end)|join("; "))|gsub("[\n\t]";" ")|.[0:160]),
                            (((.via//[])|map(select(type=="object").url)|.[0]) // "") ] | @tsv' "$na" 2>/dev/null | sort -u)
        [ "$n" -gt 0 ] && warn "npm audit: $n vulnerable package(s)" || ok "npm audit: clean (prod)"
        DEP_ANY=$n; scanned=1
      else
        deps_error "npm audit produced no parseable JSON"
      fi
    else
      deps_error "node stack with no package-lock.json — dependencies NOT scanned (run npm i --package-lock-only)"
    fi
  fi

  if [ "$scanned" = 1 ]; then
    if [ -n "${LOCK_MISSING// /}" ]; then
      deps_error "scanned, but these stacks have no lockfile and were NOT covered:${LOCK_MISSING}"
    elif [ "$DEP_ANY" -gt 0 ]; then set_status deps findings "$DEP_ANY CVE(s)"
    else set_status deps ok "0 CVEs"; fi
  elif [ "$DEPS_ERRORED" = 1 ]; then
    :   # already reported
  else
    deps_error "no dependency scanner available (trivy, grype, or npm) — dependencies NOT scanned"
  fi
fi

# ═══════════════════════════════════════════════════════════════════
# 4. IaC / container misconfig
# ═══════════════════════════════════════════════════════════════════
head2 "4. IaC & container misconfig"
IAC_STACK=0
for s in docker docker-compose terraform helm; do has_stack "$s" && IAC_STACK=1; done
[ -n "$(findx -name '*.yaml' -o -name '*.yml' | head -1)" ] && IAC_STACK=1   # k8s manifests
if [ "$DO_IAC" = 0 ]; then
  skip "IaC scan" "--skip-iac"; set_status iac skipped "--skip-iac"
elif [ "$IAC_STACK" = 0 ]; then
  skip "IaC scan" "no Dockerfile / terraform / k8s / helm files found"; set_status iac skipped "no IaC files"
elif ! have trivy; then
  pass_error iac "IaC files present but trivy is not installed — misconfigurations NOT scanned"
else
  ti="$OUTDIR/trivy-iac.json"; rm -f "$ti"
  ti_args=(config --severity MEDIUM,HIGH,CRITICAL --quiet --format json --output "$ti")
  for e in "${EXCLUDES[@]}"; do ti_args+=(--skip-dirs "$e"); done
  trivy "${ti_args[@]}" "$TARGET" >/dev/null 2>"$OUTDIR/.trivy-iac.err"; ti_rc=$?
  if [ ! -f "$ti" ] || ! jq -e . "$ti" >/dev/null 2>&1; then
    pass_error iac "trivy config exited $ti_rc and produced no parseable JSON"
  elif pe="$(trivy_parse_errors "$OUTDIR/.trivy-iac.err")" && [ -n "$pe" ]; then
    # A Terraform/YAML syntax error makes trivy report "0 misconfigurations" —
    # unparsed files are unscanned files, not clean ones.
    pass_error iac "trivy config could not parse one or more IaC files (unparsed files are NOT scanned): $(printf '%s' "$pe" | tr '\n' ' ' | head -c 240)"
  else
    c=0; h=0; m=0
    while IFS=$'\t' read -r sev id target lineno title url; do
      [ -z "${id:-}" ] && continue
      case "$sev" in
        CRITICAL) c=$((c+1)); vs=critical;;
        HIGH)     h=$((h+1)); vs=high;;
        *)        m=$((m+1)); vs=medium;;
      esac
      add_finding trivy-config "$vs" "$id" "$(rel "$target")" "$lineno" "$title" "$url"
    done < <(jq -r '.Results[]? | .Target as $t | (.Misconfigurations//[])[]
                    | [ .Severity, (.ID//"misconfig"), $t,
                        ((.CauseMetadata.StartLine//0)|tostring),
                        (((.Title//"misconfiguration") + " — " + (.Message//""))|gsub("[\n\t]";" ")|.[0:180]),
                        (.PrimaryURL//"") ] | @tsv' "$ti" 2>/dev/null | sort -u)
    [ "$c" -gt 0 ] && bad  "trivy config: $c CRITICAL misconfig(s)"
    [ "$h" -gt 0 ] && warn "trivy config: $h HIGH misconfig(s)"
    [ "$m" -gt 0 ] && say  "  ${C_D}trivy config: $m MEDIUM misconfig(s)${C_0}"
    [ $((c+h+m)) -eq 0 ] && ok "trivy config: 0 MEDIUM+ misconfigs"
    if [ $((c+h+m)) -gt 0 ]; then set_status iac findings "$c critical, $h high, $m medium"; else set_status iac ok "0 misconfigs"; fi
  fi
fi

# ═══════════════════════════════════════════════════════════════════
# 5. dynamic (opt-in, read-only)
# ═══════════════════════════════════════════════════════════════════
if [ "$DYNAMIC" = 1 ] && [ -z "$URL" ]; then
  head2 "5. Dynamic checks"
  pass_error dynamic "--dynamic given without --url — nothing was checked"
elif [ "$DYNAMIC" = 1 ]; then
  head2 "5. Dynamic checks (read-only) — $URL"
  HDRS_ALL="$OUTDIR/.headers.txt"
  curl -sSL -D "$HDRS_ALL" -o /dev/null --max-time 20 "$URL" >/dev/null 2>"$OUTDIR/.curl.err"; cu_rc=$?
  if [ "$cu_rc" -ne 0 ] || [ ! -s "$HDRS_ALL" ]; then
    pass_error dynamic "could not reach $URL (curl exit $cu_rc) — headers/TLS NOT verified"
  else
    # 0.1.0 grepped the CONCATENATED headers of every redirect hop, so a header
    # set on an HTTP->HTTPS redirect by a CDN made the app look compliant.
    # Evaluate ONLY the final response.
    hops=$(tr -d '\r' < "$HDRS_ALL" | grep -c '^HTTP/' || true)
    hdrs="$(tr -d '\r' < "$HDRS_ALL" | awk '/^HTTP\//{n=NR} {a[NR]=$0} END{for(i=n;i<=NR;i++) print a[i]}')"
    status_line="$(printf '%s' "$hdrs" | head -1)"
    [ "$hops" -gt 1 ] && say "  ${C_D}followed $((hops-1)) redirect(s); evaluating final response only: $status_line${C_0}" \
                      || say "  ${C_D}final response: $status_line${C_0}"

    hdr_has() { printf '%s\n' "$hdrs" | grep -iq "^$1:"; }
    hdr_val() { printf '%s\n' "$hdrs" | grep -i "^$1:" | head -1 | sed 's/^[^:]*:[[:space:]]*//'; }
    dyn_n=0
    checkhdr() { # display-name  header-name  severity  rule
      if hdr_has "$2"; then ok "$1 present"; else
        bad "$1 MISSING"; dyn_n=$((dyn_n+1))
        add_finding dynamic "$3" "$4" "$URL" 0 "Missing response header: $1" \
          "https://developer.mozilla.org/docs/Web/HTTP/Headers/$1"
      fi; }

    # HSTS — also check the directive is actually useful
    if hdr_has "strict-transport-security"; then
      hv="$(hdr_val strict-transport-security)"
      ma="$(printf '%s' "$hv" | grep -oiE 'max-age=[0-9]+' | head -1 | cut -d= -f2)"
      if [ -n "${ma:-}" ] && [ "$ma" -lt 15552000 ]; then
        warn "HSTS present but max-age=$ma (< 180 days)"; dyn_n=$((dyn_n+1))
        add_finding dynamic low "hsts-short-max-age" "$URL" 0 "HSTS max-age=$ma is below the recommended 15552000" ""
      else ok "Strict-Transport-Security present ($hv)"; fi
    else
      bad "Strict-Transport-Security MISSING"; dyn_n=$((dyn_n+1))
      add_finding dynamic medium "missing-hsts" "$URL" 0 "Missing response header: Strict-Transport-Security" ""
    fi

    if hdr_has "content-security-policy"; then ok "Content-Security-Policy present (enforcing)"
    elif hdr_has "content-security-policy-report-only"; then
      warn "Content-Security-Policy is Report-Only (tune, then enforce)"; dyn_n=$((dyn_n+1))
      add_finding dynamic low "csp-report-only" "$URL" 0 "CSP present but Report-Only — promote to enforcing after tuning" ""
    else
      bad "Content-Security-Policy MISSING"; dyn_n=$((dyn_n+1))
      add_finding dynamic medium "missing-csp" "$URL" 0 "Missing response header: Content-Security-Policy" ""
    fi

    checkhdr "X-Content-Type-Options" "x-content-type-options" low  "missing-nosniff"
    checkhdr "Referrer-Policy"        "referrer-policy"        low  "missing-referrer-policy"
    checkhdr "Permissions-Policy"     "permissions-policy"     low  "missing-permissions-policy"
    if hdr_has "x-frame-options" || printf '%s' "$hdrs" | grep -iq 'frame-ancestors'; then
      ok "X-Frame-Options / frame-ancestors present"
    else
      bad "Clickjacking protection MISSING (X-Frame-Options / frame-ancestors)"; dyn_n=$((dyn_n+1))
      add_finding dynamic low "missing-frame-protection" "$URL" 0 "No X-Frame-Options or CSP frame-ancestors" ""
    fi

    # CORS — wildcard is worse when credentials are allowed
    aco="$(hdr_val access-control-allow-origin)"
    acc="$(hdr_val access-control-allow-credentials)"
    if [ "$aco" = "*" ]; then
      if printf '%s' "$acc" | grep -iq true; then
        bad "CORS: wildcard origin WITH credentials allowed"; dyn_n=$((dyn_n+1))
        add_finding dynamic high "cors-wildcard-with-credentials" "$URL" 0 \
          "Access-Control-Allow-Origin: * together with Allow-Credentials: true" ""
      else
        warn "CORS: wildcard Access-Control-Allow-Origin"; dyn_n=$((dyn_n+1))
        add_finding dynamic medium "cors-wildcard" "$URL" 0 "Access-Control-Allow-Origin: *" ""
      fi
    else ok "no wildcard CORS on this response"; fi

    # Cookies — evaluated PER COOKIE. 0.1.0 passed if *any* cookie had
    # HttpOnly, so a session cookie missing it hid behind a compliant tracker.
    ck_total=0
    while IFS= read -r ck; do
      [ -z "$ck" ] && continue
      ck_total=$((ck_total+1))
      name="$(printf '%s' "$ck" | sed 's/^[^:]*:[[:space:]]*//; s/=.*//')"
      sensitive=0
      printf '%s' "$name" | grep -qiE '(sess|sid|auth|token|jwt|login|remember|csrf)' && sensitive=1
      sev=low; [ "$sensitive" = 1 ] && sev=high
      miss=""
      printf '%s' "$ck" | grep -iq 'httponly'  || miss="$miss HttpOnly"
      printf '%s' "$ck" | grep -iq 'secure'    || miss="$miss Secure"
      printf '%s' "$ck" | grep -iq 'samesite'  || miss="$miss SameSite"
      if [ -n "$miss" ]; then
        dyn_n=$((dyn_n+1))
        if [ "$sensitive" = 1 ]; then bad "cookie '$name' (session-like) missing:$miss"
        else warn "cookie '$name' missing:$miss"; fi
        add_finding dynamic "$sev" "cookie-flags.$name" "$URL" 0 \
          "Set-Cookie '$name' missing:$miss" \
          "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"
      else ok "cookie '$name': HttpOnly + Secure + SameSite"; fi
    done < <(printf '%s\n' "$hdrs" | grep -i '^set-cookie:')
    [ "$ck_total" = 0 ] && say "  ${C_D}no cookies on this response${C_0}"

    srv="$(hdr_val server)"
    if printf '%s' "$srv" | grep -qiE '[0-9]+\.[0-9]+'; then
      warn "Server banner leaks version: $srv"; dyn_n=$((dyn_n+1))
      add_finding dynamic low "server-banner" "$URL" 0 "Server header leaks software version: $srv" ""
    fi

    # ── TLS: actively probe legacy protocols + check cert expiry ──
    # 0.1.0 only looked at what OpenSSL happened to negotiate, so a server that
    # still ACCEPTS TLS 1.0 was reported as "modern".
    if printf '%s' "$URL" | grep -q '^https' && have openssl; then
      hostp="${URL#https://}"; hostp="${hostp%%/*}"
      case "$hostp" in
        \[*\]*) host="${hostp%%]*}"; host="${host#[}"; port="${hostp##*]:}"; [ "$port" = "$hostp" ] && port=443;;
        *:*)    host="${hostp%%:*}"; port="${hostp##*:}";;
        *)      host="$hostp"; port=443;;
      esac
      legacy=""
      for p in tls1 tls1_1; do
        if openssl s_client -help 2>&1 | grep -q -- "-$p\b"; then
          if echo | openssl s_client -"$p" -connect "$host:$port" -servername "$host" 2>/dev/null \
             | grep -q 'BEGIN CERTIFICATE'; then legacy="$legacy ${p/_/.}"; fi
        fi
      done
      if [ -n "$legacy" ]; then
        bad "TLS: server ACCEPTS legacy protocol(s):$legacy"; dyn_n=$((dyn_n+1))
        add_finding dynamic high "tls-legacy-protocol" "$URL" 0 "Server accepts legacy TLS:$legacy — disable TLS 1.0/1.1" ""
      else ok "TLS: legacy protocols (1.0/1.1) refused"; fi

      enddate="$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null \
                 | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
      if [ -n "$enddate" ]; then
        exp_s="$(date -j -f '%b %e %T %Y %Z' "$enddate" +%s 2>/dev/null || date -d "$enddate" +%s 2>/dev/null || echo '')"
        if [ -n "$exp_s" ]; then
          days=$(( (exp_s - $(date +%s)) / 86400 ))
          if [ "$days" -lt 0 ]; then
            bad "TLS: certificate EXPIRED ($enddate)"; dyn_n=$((dyn_n+1))
            add_finding dynamic critical "tls-cert-expired" "$URL" 0 "TLS certificate expired on $enddate" ""
          elif [ "$days" -lt 21 ]; then
            warn "TLS: certificate expires in $days day(s)"; dyn_n=$((dyn_n+1))
            add_finding dynamic medium "tls-cert-expiring" "$URL" 0 "TLS certificate expires in $days days ($enddate)" ""
          else ok "TLS: certificate valid for $days more day(s)"; fi
        fi
      fi
    elif printf '%s' "$URL" | grep -q '^http://'; then
      bad "target is plain HTTP — no transport security"; dyn_n=$((dyn_n+1))
      add_finding dynamic high "no-tls" "$URL" 0 "Target served over plain HTTP; use HTTPS + HSTS" ""
    fi

    [ "$dyn_n" -gt 0 ] && set_status dynamic findings "$dyn_n issue(s)" || set_status dynamic ok "0 issues"
  fi
else
  head2 "5. Dynamic checks"; skip "dynamic checks" "pass --url https://your.app to enable"
  set_status dynamic skipped "no --url"
fi

# ═══════════════════════════════════════════════════════════════════
# baseline: split findings into active (gated) and accepted (suppressed)
# ═══════════════════════════════════════════════════════════════════
ERRORS=$(jq -s '[.[]|select(.status=="error")]|length' "$STATUS")

# --write-baseline: accept everything currently found. Existing entries keep
# their original date and reason so re-running never erases why something was
# accepted; only genuinely new findings are added.
if [ "$WRITE_BASELINE" = 1 ]; then
  head2 "Baseline"
  [ -n "$BASELINE" ] || BASELINE="$TARGET/.vibecheck-baseline.json"
  today="$(date '+%Y-%m-%d')"
  prev="$OUTDIR/.prev-baseline.json"
  if [ -f "$BASELINE" ] && jq -e '.entries' "$BASELINE" >/dev/null 2>&1; then
    cp "$BASELINE" "$prev"
  else
    printf '{"version":1,"entries":[]}' > "$prev"
  fi
  jq -s --slurpfile prev "$prev" --arg today "$today" '
    ($prev[0].entries // []) as $old |
    ($old | map({key:.fingerprint, value:.}) | from_entries) as $bykey |
    { version: 1,
      generated: $today,
      note: "VibeCheck accepted findings. Entries suppress a finding from the exit-code gate; they are still listed in the report. Delete an entry to re-gate it.",
      entries: ( group_by(.fingerprint)
                 | map( (.[0] | {fingerprint, tool, rule, file, title}) + {occurrences: length} )
                 | map( . as $n
                        | ($bykey[$n.fingerprint] // null) as $o
                        | $n + { added: ($o.added // $today),
                                 reason: ($o.reason // "") } )
                 | sort_by(.tool, .rule, .file) )
    }' "$FINDINGS" > "$BASELINE"
  n_new=$(jq -s --slurpfile prev "$prev" '
    ([$prev[0].entries[]?.fingerprint]) as $old |
    [ .[] | select(.fingerprint as $f | ($old|index($f))|not) ] | unique_by(.fingerprint) | length' "$FINDINGS")
  n_all=$(jq '.entries|length' "$BASELINE")
  ok "baseline written: $BASELINE ($n_all accepted, $n_new newly added)"
  say "  ${C_D}add a 'reason' to each entry so the next reader knows why it was accepted${C_0}"
  say "  ${C_D}re-run without --write-baseline to scan against it${C_0}"
  exit 0
fi

BASE_N=0; BASE_STALE=0
if [ -n "$BASELINE" ] && [ "$USE_BASELINE" = 1 ] && [ -f "$BASELINE" ]; then
  jq -r '.entries[]?.fingerprint' "$BASELINE" 2>/dev/null | sort -u > "$OUTDIR/.bl-fps"
  # An accepted finding is suppressed from the gate but still reported.
  jq -c --slurpfile bl <(jq '[.entries[]?.fingerprint]' "$BASELINE") \
    'select((.fingerprint as $f | $bl[0] | index($f)) != null)' "$FINDINGS" > "$ACCEPTED"
  jq -c --slurpfile bl <(jq '[.entries[]?.fingerprint]' "$BASELINE") \
    'select((.fingerprint as $f | $bl[0] | index($f)) == null)' "$FINDINGS" > "$ACTIVE"
  BASE_N=$(jq -s 'length' "$ACCEPTED")
  head2 "Baseline"
  say "  ${C_D}$BASELINE${C_0}"
  [ "$BASE_N" -gt 0 ] && warn "$BASE_N finding(s) accepted by baseline — excluded from the gate, still listed in the report" \
                      || ok "no findings matched the baseline"
  # Staleness: prompt re-review without breaking the build on a timer.
  while IFS=$'\t' read -r fpr added; do
    [ -z "${added:-}" ] && continue
    d="$(days_since "$added")"
    [ -n "$d" ] && [ "$d" -gt "$BASELINE_STALE_DAYS" ] && BASE_STALE=$((BASE_STALE+1))
  done < <(jq -r '.entries[]? | [.fingerprint, (.added//"")] | @tsv' "$BASELINE" 2>/dev/null)
  [ "$BASE_STALE" -gt 0 ] && warn "$BASE_STALE baseline entr(ies) older than $BASELINE_STALE_DAYS days — re-review whether they are still acceptable"
  # One fingerprint can cover several occurrences: many scanners emit an
  # identical message for every hit of a rule in a file, and the line number is
  # deliberately not part of the identity. Without this check, a NEW occurrence
  # of an already-accepted rule in an already-accepted file would be suppressed
  # silently. Compare against the count recorded when the entry was accepted.
  BASE_GREW=0
  while IFS=$'\t' read -r fpr was; do
    [ -z "${fpr:-}" ] && continue
    [ -z "${was:-}" ] || [ "$was" = "null" ] && continue   # pre-0.3.1 entry, no count recorded
    now=$(jq -s --arg f "$fpr" '[.[]|select(.fingerprint==$f)]|length' "$ACCEPTED")
    if [ "$now" -gt "$was" ]; then
      BASE_GREW=$((BASE_GREW+1))
      warn "baseline entry $fpr now suppresses $now finding(s), was $was when accepted — a new occurrence is being hidden"
      jq -r --arg f "$fpr" 'select(.fingerprint==$f) | "      · \(.file):\(.line)"' "$ACCEPTED"
    fi
  done < <(jq -r '.entries[]? | [.fingerprint, ((.occurrences // "null")|tostring)] | @tsv' "$BASELINE" 2>/dev/null)
  # An unused entry usually means the finding was fixed: worth pruning.
  bl_total=$(jq '.entries|length' "$BASELINE")
  unused=$((bl_total - BASE_N))
  [ "$unused" -gt 0 ] && say "  ${C_D}$unused baseline entr(ies) matched nothing (fixed or moved) — prune with --write-baseline${C_0}"
else
  cp "$FINDINGS" "$ACTIVE"
fi

# ── diff scope (PR mode) ──
# Gate only on findings in files this change touched. Pre-existing findings
# elsewhere are still reported, just not gated — that is the point: a PR should
# fail for what it introduces, not for what it inherited.
DIFF_N=0
if [ -n "$DIFF_REF" ]; then
  head2 "Diff scope"
  if [ ! -d "$TARGET/.git" ] && ! git -C "$TARGET" rev-parse --git-dir >/dev/null 2>&1; then
    pass_error diff "--diff $DIFF_REF requires a git repository — scope could not be determined"
  elif ! git -C "$TARGET" rev-parse --verify --quiet "$DIFF_REF" >/dev/null 2>&1; then
    # Fail closed: silently scoping to nothing would turn --diff into "gate on
    # nothing", which is exactly the fail-open behaviour this tool refuses.
    pass_error diff "git ref '$DIFF_REF' not found — cannot determine what changed (fetch it, or drop --diff)"
  else
    CHANGED="$OUTDIR/.changed-files"
    prefix="$(git -C "$TARGET" rev-parse --show-prefix 2>/dev/null)"
    { git -C "$TARGET" diff --name-only "$DIFF_REF...HEAD" 2>/dev/null
      git -C "$TARGET" diff --name-only HEAD 2>/dev/null; } \
      | sed "s|^$prefix||" | sed '/^$/d' | sort -u > "$CHANGED"
    n_changed=$(wc -l < "$CHANGED" | tr -d ' ')
    say "  ${C_D}$n_changed file(s) changed vs $DIFF_REF${C_0}"
    if [ "$n_changed" -eq 0 ]; then
      ok "no files changed — nothing to gate on"
    fi
    OUTSCOPE="$OUTDIR/.outscope.jsonl"
    # Dynamic findings describe the running application, not a file in the diff,
    # so they always stay in scope.
    jq -c --slurpfile ch <(jq -R -s 'split("\n")|map(select(length>0))' "$CHANGED") \
      'select(.tool=="dynamic" or (.file as $f | $ch[0] | index($f)) != null)' "$ACTIVE" > "$OUTDIR/.inscope.jsonl"
    jq -c --slurpfile ch <(jq -R -s 'split("\n")|map(select(length>0))' "$CHANGED") \
      'select(.tool!="dynamic" and (.file as $f | $ch[0] | index($f)) == null)' "$ACTIVE" > "$OUTSCOPE"
    DIFF_N=$(jq -s 'length' "$OUTSCOPE")
    mv "$OUTDIR/.inscope.jsonl" "$ACTIVE"
    [ "$DIFF_N" -gt 0 ] && warn "$DIFF_N pre-existing finding(s) outside the diff — reported, not gated" \
                        || ok "no pre-existing findings outside the diff"
    set_status diff ok "$n_changed file(s) changed vs $DIFF_REF; $DIFF_N finding(s) out of scope"
  fi
fi

# ═══════════════════════════════════════════════════════════════════
# outputs: report.md · findings.json · SARIF
# ═══════════════════════════════════════════════════════════════════
# Recompute AFTER every pass, including the baseline and diff blocks above.
# Reading a value captured earlier would drop errors raised by those blocks and
# let an incomplete scan exit 0 — the fail-open behaviour this tool exists to
# prevent.
ERRORS=$(jq -s '[.[]|select(.status=="error")]|length' "$STATUS")

CRIT=$(sev_count critical); HIGH=$(sev_count high); MED=$(sev_count medium); LOW=$(sev_count low)
TOTAL=$((CRIT+HIGH+MED+LOW))

# out_of_scope is included so the machine-readable output is complete: the raw
# JSONL files are dot-prefixed internals and CI artifact uploads skip them.
jq -s '{active: ., accepted: $acc[0], out_of_scope: $oos[0]}' \
  --slurpfile acc <(jq -s '.' "$ACCEPTED") \
  --slurpfile oos <(jq -s '.' "$OUTDIR/.outscope.jsonl" 2>/dev/null || echo '[]') \
  "$ACTIVE" > "$OUTDIR/findings.json"

{
  echo "# VibeCheck security report"
  echo
  echo "- Target: \`$TARGET\`"
  echo "- Date: $STAMP"
  [ -n "$URL" ] && echo "- Dynamic target: $URL"
  echo "- Stack: \`$(echo "$STACK" | tr -s ' ' | sed 's/^ //')\`"
  echo "- Tool: VibeCheck v$VERSION"
  echo
  echo "## Pass status"
  echo
  echo "| Pass | Status | Detail |"
  echo "|---|---|---|"
  jq -rs '.[] | "| \(.pass) | \(if .status=="error" then "⨯ **ERROR**" elif .status=="findings" then "✗ findings" elif .status=="skipped" then "— skipped" else "✓ ok" end) | \(.detail) |"' "$STATUS"
  echo
  if [ "$ERRORS" -gt 0 ]; then
    echo "> ⚠️ **$ERRORS pass(es) could not complete.** Those areas were NOT scanned —"
    echo "> treat them as unknown, not clean."
    echo
  fi
  echo "## Summary"
  echo
  echo "| Severity | Count |"
  echo "|---|---|"
  echo "| Critical | $CRIT |"
  echo "| High | $HIGH |"
  echo "| Medium | $MED |"
  echo "| Low | $LOW |"
  echo
  if [ "$TOTAL" -gt 0 ]; then
    echo "## Findings"
    echo
    for s in critical high medium low; do
      n=$(sev_count "$s")
      [ "$n" -eq 0 ] && continue
      echo "### $(printf '%s' "$s" | tr '[:lower:]' '[:upper:]') ($n)"
      echo
      echo "| Tool | Rule | Location | Detail |"
      echo "|---|---|---|---|"
      jq -rs --arg s "$s" '.[] | select(.severity==$s)
        | "| \(.tool) | `\(.rule)` | \(if .file=="" then "—" else "`\(.file)\(if .line>0 then ":\(.line)" else "" end)`" end) | \(.title|gsub("\\|";"\\\\|")) \(if .help=="" then "" else "([ref](\(.help)))" end) |"' "$ACTIVE"
      echo
    done
  fi
  if [ "$DIFF_N" -gt 0 ]; then
    echo "## Outside the diff (not gated)"
    echo
    echo "Pre-existing findings in files not changed vs \`$DIFF_REF\`. Reported for awareness; they do not affect the exit code in \`--diff\` mode."
    echo
    echo "| Severity | Tool | Rule | Location | Detail |"
    echo "|---|---|---|---|---|"
    jq -rs '.[] | "| \(.severity) | \(.tool) | `\(.rule)` | \(if .file=="" then "—" else "`\(.file)`" end) | \(.title|gsub("\\|";"\\\\|")) |"' "$OUTDIR/.outscope.jsonl"
    echo
  fi
  if [ "$BASE_N" -gt 0 ]; then
    echo "## Accepted (baseline)"
    echo
    echo "Suppressed from the exit-code gate by \`$(basename "$BASELINE")\`. Still present in the code."
    echo
    echo "| Severity | Tool | Rule | Location | Detail |"
    echo "|---|---|---|---|---|"
    jq -rs '.[] | "| \(.severity) | \(.tool) | `\(.rule)` | \(if .file=="" then "—" else "`\(.file)`" end) | \(.title|gsub("\\|";"\\\\|")) |"' "$ACCEPTED"
    echo
  fi
  echo "_Raw scanner output in \`$OUTDIR/\`. SARIF: \`$(basename "$SARIF")\`._"
  echo "_Scanners produce false positives — triage before acting._"
} > "$REPORT"

# ── SARIF 2.1.0 (GitHub Code Scanning ingests security-severity) ──
jq -s --arg ver "$VERSION" --arg uri "$TOOL_URL" '
  def level: if . == "critical" or . == "high" then "error"
             elif . == "medium" then "warning" else "note" end;
  def secsev: if . == "critical" then "9.5" elif . == "high" then "8.0"
              elif . == "medium" then "5.0" else "3.0" end;
  {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "VibeCheck", version: $ver, informationUri: $uri,
        rules: ( map({
                   id: (.tool + "." + .rule),
                   name: .rule,
                   shortDescription: { text: (.title[0:120]) },
                   defaultConfiguration: { level: (.severity|level) },
                   properties: ({ "security-severity": (.severity|secsev),
                                  tags: ["security", .tool] })
                 } + (if .help == "" then {} else { helpUri: .help } end))
                 | unique_by(.id) )
      }},
      automationDetails: { id: ("vibecheck/" + $ver) },
      results: map({
        ruleId: (.tool + "." + .rule),
        level: (.severity|level),
        message: { text: .title },
        partialFingerprints: { vibecheckFingerprint: .fingerprint },
        properties: { "security-severity": (.severity|secsev), tool: .tool },
        locations: [{ physicalLocation: (
          { artifactLocation: { uri: (if .file == "" then "." else .file end) } }
          + (if .line > 0 then { region: { startLine: .line } } else {} end)
        )}]
      })
    }]
  }' "$ACTIVE" > "$SARIF" 2>/dev/null || {
    err "failed to generate SARIF"; }

# ── gate (computed before the report so the verdict can be rendered in it) ──
gate=0; reason=""
case "$FAIL_ON" in
  never)    gate=0;;
  any)      [ "$TOTAL" -gt 0 ] && { gate=1; reason="any finding"; };;
  low)      [ $((CRIT+HIGH+MED+LOW)) -gt 0 ] && { gate=1; reason="low+"; };;
  medium)   [ $((CRIT+HIGH+MED)) -gt 0 ] && { gate=1; reason="medium+"; };;
  high)     [ $((CRIT+HIGH)) -gt 0 ] && { gate=1; reason="high+"; };;
  critical) [ "$CRIT" -gt 0 ] && { gate=1; reason="critical"; };;
esac

if [ "$ERRORS" -gt 0 ] && [ "$FAIL_ON_ERROR" = 1 ]; then
  VERDICT="INCOMPLETE"; V_CLASS="incomplete"; RC=3
  V_TEXT="$ERRORS scan pass(es) could not complete. Those areas were NOT examined and are unknown — not clean."
elif [ "$gate" = 1 ]; then
  VERDICT="FAIL"; V_CLASS="fail"; RC=1
  V_TEXT="Findings at or above the '$FAIL_ON' threshold ($reason)."
else
  VERDICT="PASS"; V_CLASS="pass"; RC=0
  V_TEXT="No findings above the '$FAIL_ON' threshold."
  [ "$ERRORS" -gt 0 ] && V_TEXT="$V_TEXT Note: $ERRORS pass(es) were incomplete and fail-on-error was disabled."
fi

# ── HTML report (self-contained, print/PDF-ready) ──
# Severity uses the reserved status palette and always pairs colour with an icon
# and a text label — two of these steps are sub-3:1 on a light surface, so colour
# never carries meaning on its own.
sev_icon() { case "$1" in critical) printf '✕';; high) printf '▲';; medium) printf '●';; *) printf '▪';; esac; }

{
cat <<'HTMLHEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeCheck Security Report</title>
<style>
  :root{
    --ink:#1a1a19; --ink-2:#4a4a47; --muted:#6b6b68; --rule:#e2e2df;
    --surface:#fff; --surface-2:#faf9f7; --accent:#2b6cb0;
    --crit:#d03b3b; --high:#ec835a; --med:#fab219; --low:#8a8a86; --good:#0ca30c;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--surface);color:var(--ink);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased}
  .wrap{max-width:60rem;margin:0 auto;padding:2.5rem 2rem 4rem}
  header{border-bottom:2px solid var(--ink);padding-bottom:1.25rem;margin-bottom:1.75rem}
  .brand{font-size:.75rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:0 0 .35rem}
  h1{font-size:1.9rem;line-height:1.2;margin:0 0 1rem;letter-spacing:-.01em}
  h2{font-size:1.15rem;margin:2.5rem 0 .85rem;padding-bottom:.4rem;border-bottom:1px solid var(--rule);letter-spacing:-.005em}
  h3{font-size:.95rem;margin:1.75rem 0 .6rem;display:flex;align-items:center;gap:.5rem}
  p{margin:.6rem 0}
  .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:.5rem 1.5rem;font-size:.84rem}
  .meta div{display:flex;gap:.5rem;min-width:0}
  .meta div.wide{grid-column:1/-1}   /* long paths/URLs get the full row */
  .meta dt{color:var(--muted);min-width:5.5rem;flex:none}
  .meta dd{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
           overflow-wrap:anywhere;min-width:0}
  .verdict{border:1px solid;border-left-width:5px;border-radius:5px;padding:1rem 1.15rem;margin:1.5rem 0}
  .verdict .vlabel{font-weight:700;font-size:1rem;display:flex;align-items:center;gap:.5rem;margin-bottom:.25rem}
  .verdict p{margin:0;font-size:.9rem;color:var(--ink-2)}
  .verdict.pass{border-color:var(--good);background:#f2fbf2}
  .verdict.fail{border-color:var(--crit);background:#fdf3f3}
  .verdict.incomplete{border-color:var(--crit);background:#fdf3f3}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin:1.25rem 0}
  .tile{border:1px solid var(--rule);border-top:3px solid;border-radius:5px;padding:.8rem .9rem;background:var(--surface-2)}
  .tile .ico{font-size:.8rem;line-height:1}
  .tile .num{display:block;font-size:2rem;font-weight:650;line-height:1.1;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
  .tile .lab{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:.35rem}
  .t-crit{border-top-color:var(--crit)} .t-crit .ico{color:var(--crit)}
  .t-high{border-top-color:var(--high)} .t-high .ico{color:var(--high)}
  .t-med{border-top-color:var(--med)}  .t-med  .ico{color:var(--med)}
  .t-low{border-top-color:var(--low)}  .t-low  .ico{color:var(--low)}
  table{width:100%;border-collapse:collapse;font-size:.84rem;margin:.5rem 0 1rem}
  thead{display:table-header-group}
  th{text-align:left;font-size:.7rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
     border-bottom:1px solid var(--ink);padding:.45rem .6rem .4rem;font-weight:600}
  td{border-bottom:1px solid var(--rule);padding:.55rem .6rem;vertical-align:top}
  tr{break-inside:avoid;page-break-inside:avoid}
  code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
  td.loc{white-space:nowrap;color:var(--ink-2)}
  .pill{display:inline-flex;align-items:center;gap:.3rem;font-size:.7rem;font-weight:600;
        letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
  .s-critical{color:var(--crit)} .s-high{color:var(--high)}
  .s-medium{color:#8a6100} .s-low{color:var(--low)}
  .st-ok{color:var(--good)} .st-error{color:var(--crit);font-weight:700}
  .st-findings{color:var(--crit)} .st-skipped{color:var(--muted)}
  .note{background:var(--surface-2);border:1px solid var(--rule);border-radius:5px;
        padding:.85rem 1rem;font-size:.85rem;color:var(--ink-2);margin:1rem 0}
  .note strong{color:var(--ink)}
  .scope{border-left:3px solid var(--muted);padding:.15rem 0 .15rem .9rem;margin:1rem 0;
         font-size:.85rem;color:var(--ink-2)}
  footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--rule);
         font-size:.78rem;color:var(--muted)}
  a{color:var(--accent)} a:hover{text-decoration:underline}
  .empty{color:var(--muted);font-style:italic}
  @media (max-width:640px){ .kpis{grid-template-columns:repeat(2,1fr)} .wrap{padding:1.5rem 1rem 3rem} }
  @media print{
    @page{margin:16mm}
    .wrap{max-width:none;padding:0}
    body{font-size:10.5pt}
    h2{margin-top:1.4rem} h1{font-size:1.6rem}
    .verdict,.note,.tile{background:#fff!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
    h2,h3{break-after:avoid;page-break-after:avoid}
    a{text-decoration:none}
  }
</style>
</head>
<body>
<div class="wrap">
HTMLHEAD

# ── header + metadata ──
printf '<header>\n<p class="brand">Automated Security Audit</p>\n<h1>VibeCheck Security Report</h1>\n<dl class="meta">\n'
printf '<div class="wide"><dt>Target</dt><dd>%s</dd></div>\n' "$(printf '%s' "$TARGET" | sed 's/&/\&amp;/g;s/</\&lt;/g')"
printf '<div><dt>Scanned</dt><dd>%s</dd></div>\n' "$STAMP"
[ -n "$URL" ] && printf '<div><dt>Dynamic</dt><dd>%s</dd></div>\n' "$(printf '%s' "$URL" | sed 's/&/\&amp;/g;s/</\&lt;/g')"
printf '<div><dt>Stack</dt><dd>%s</dd></div>\n' "$(echo "$STACK" | tr -s ' ' | sed 's/^ //;s/ $//;s/&/\&amp;/g;s/</\&lt;/g')"
printf '<div><dt>Threshold</dt><dd>%s</dd></div>\n' "$FAIL_ON"
printf '<div><dt>Tool</dt><dd>VibeCheck v%s</dd></div>\n' "$VERSION"
printf '</dl>\n</header>\n'

# ── verdict ──
case "$VERDICT" in
  PASS)       vicon="✓";;
  FAIL)       vicon="✗";;
  *)          vicon="⨯";;
esac
printf '<div class="verdict %s"><div class="vlabel"><span>%s</span><span>%s</span></div><p>%s</p></div>\n' \
  "$V_CLASS" "$vicon" "$VERDICT" "$V_TEXT"

# ── executive summary: KPI row (headline numbers, not a chart) ──
printf '<h2>Summary of findings</h2>\n<div class="kpis">\n'
for s in critical high medium low; do
  case "$s" in critical) cls=t-crit; n=$CRIT;; high) cls=t-high; n=$HIGH;; medium) cls=t-med; n=$MED;; low) cls=t-low; n=$LOW;; esac
  printf '<div class="tile %s"><span class="num">%s</span><span class="lab"><span class="ico">%s</span>%s</span></div>\n' \
    "$cls" "$n" "$(sev_icon "$s")" "$s"
done
printf '</div>\n'
printf '<p style="font-size:.85rem;color:var(--muted)">%s finding(s) counted across %s scan pass(es)' \
  "$TOTAL" "$(jq -s 'length' "$STATUS")"
[ "$BASE_N" -gt 0 ] && printf ', plus %s accepted via baseline (listed below, excluded from the verdict)' "$BASE_N"
printf '.</p>\n'

# ── coverage / pass status ──
printf '<h2>Scan coverage</h2>\n'
printf '<p>Every pass reports its own status. A pass marked <strong>ERROR</strong> did not complete: that area was <em>not examined</em>, and its absence of findings means nothing.</p>\n'
printf '<table><thead><tr><th>Pass</th><th>Status</th><th>Detail</th></tr></thead><tbody>\n'
jq -rs '.[] |
  (if .status=="error" then "st-error|⨯ ERROR"
   elif .status=="findings" then "st-findings|✗ findings"
   elif .status=="skipped" then "st-skipped|— skipped"
   else "st-ok|✓ clean" end) as $s |
  "<tr><td>\(.pass)</td><td class=\"\($s|split("|")[0])\">\($s|split("|")[1])</td><td>\(.detail|@html)</td></tr>"' "$STATUS"
printf '</tbody></table>\n'

if [ "$ERRORS" -gt 0 ]; then
  printf '<div class="note"><strong>⨯ Incomplete coverage.</strong> %s pass(es) failed to run. VibeCheck fails closed: an area it could not scan is reported as unknown rather than clean.</div>\n' "$ERRORS"
fi

# ── findings ──
printf '<h2>Findings</h2>\n'
if [ "$TOTAL" -eq 0 ]; then
  printf '<p class="empty">No findings recorded at or above the reporting floor.</p>\n'
else
  for s in critical high medium low; do
    n=$(sev_count "$s"); [ "$n" -eq 0 ] && continue
    printf '<h3><span class="pill s-%s">%s %s</span><span style="color:var(--muted);font-weight:400">(%s)</span></h3>\n' \
      "$s" "$(sev_icon "$s")" "$s" "$n"
    printf '<table><thead><tr><th>Tool</th><th>Rule</th><th>Location</th><th>Detail</th></tr></thead><tbody>\n'
    jq -rs --arg s "$s" '.[] | select(.severity==$s) |
      "<tr><td>\(.tool|@html)</td><td><code>\(.rule|@html)</code></td>" +
      "<td class=\"loc\">" + (if .file=="" then "—" else "<code>\(.file|@html)\(if .line>0 then ":\(.line)" else "" end)</code>" end) + "</td>" +
      "<td>\(.title|@html)" + (if .help=="" then "" else " <a href=\"\(.help|@html)\">ref</a>" end) + "</td></tr>"' "$ACTIVE"
    printf '</tbody></table>\n'
  done
fi

# ── outside the diff — visible, but not gated in PR mode ──
if [ "$DIFF_N" -gt 0 ]; then
  printf '<h2>Outside the diff</h2>\n'
  printf '<p>%s pre-existing finding(s) in files not changed vs <code>%s</code>. Reported for awareness; they do not affect the verdict in diff mode. Run a full scan on your default branch to gate on these.</p>\n' \
    "$DIFF_N" "$(printf '%s' "$DIFF_REF" | sed 's/&/\&amp;/g;s/</\&lt;/g')"
  printf '<table><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Location</th><th>Detail</th></tr></thead><tbody>\n'
  jq -rs '.[] |
    "<tr><td><span class=\"pill s-\(.severity)\">\(.severity)</span></td><td>\(.tool|@html)</td>" +
    "<td><code>\(.rule|@html)</code></td>" +
    "<td class=\"loc\">" + (if .file=="" then "—" else "<code>\(.file|@html)</code>" end) + "</td>" +
    "<td>\(.title|@html)</td></tr>"' "$OUTDIR/.outscope.jsonl"
  printf '</tbody></table>\n'
fi

# ── accepted (baseline) — visible, but excluded from the gate ──
if [ "$BASE_N" -gt 0 ]; then
  printf '<h2>Accepted findings</h2>\n'
  printf '<p>%s finding(s) are suppressed from the exit-code gate by <code>%s</code>. They are <strong>still present in the code</strong> — accepted, not fixed.</p>\n' \
    "$BASE_N" "$(printf '%s' "$(basename "$BASELINE")" | sed 's/&/\&amp;/g;s/</\&lt;/g')"
  [ "$BASE_STALE" -gt 0 ] && printf '<div class="note"><strong>%s entr(ies) older than %s days.</strong> Re-review whether these are still acceptable.</div>\n' "$BASE_STALE" "$BASELINE_STALE_DAYS"
  printf '<table><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Location</th><th>Detail</th></tr></thead><tbody>\n'
  jq -rs '.[] |
    "<tr><td><span class=\"pill s-\(.severity)\">\(.severity)</span></td><td>\(.tool|@html)</td>" +
    "<td><code>\(.rule|@html)</code></td>" +
    "<td class=\"loc\">" + (if .file=="" then "—" else "<code>\(.file|@html)</code>" end) + "</td>" +
    "<td>\(.title|@html)</td></tr>"' "$ACCEPTED"
  printf '</tbody></table>\n'
fi

# ── methodology + scope ──
printf '<h2>Methodology &amp; scope</h2>\n'
printf '<p>VibeCheck orchestrates open-source scanners and consolidates their output. Passes run over the target directory; dynamic checks, when enabled, issue a single unauthenticated GET and a TLS handshake against the supplied URL — no payloads, no exploitation.</p>\n'
printf '<div class="scope"><strong>This is an automated scan, not a penetration test.</strong> It detects known and mechanical issues: leaked credentials, vulnerable dependencies, insecure code patterns, misconfiguration, and missing transport controls. It does <strong>not</strong> detect business-logic flaws — broken access control, multi-tenant data leakage, authorisation bypasses, or insecure workflows — which require a human reviewer who understands the application&rsquo;s intent. Scanners also produce false positives; triage before acting.</div>\n'
printf '<p style="font-size:.85rem;color:var(--muted)">Raw scanner output, SARIF, and machine-readable findings are alongside this file in <code>%s</code>.</p>\n' \
  "$(printf '%s' "$(basename "$OUTDIR")" | sed 's/&/\&amp;/g;s/</\&lt;/g')"

printf '<footer>Generated by VibeCheck v%s on %s · Threshold <code>%s</code> · Exit code %s</footer>\n' \
  "$VERSION" "$STAMP" "$FAIL_ON" "$RC"
printf '</div>\n</body>\n</html>\n'
} > "$HTML"

# ── PDF (optional) ──
if [ "$DO_PDF" = 1 ]; then
  pdf_ok=0
  CHROME=""
  for c in "google-chrome" "google-chrome-stable" "chromium" "chromium-browser" "msedge"; do
    have "$c" && { CHROME="$c"; break; }
  done
  if [ -z "$CHROME" ]; then
    for p in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
             "/Applications/Chromium.app/Contents/MacOS/Chromium" \
             "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"; do
      [ -x "$p" ] && { CHROME="$p"; break; }
    done
  fi
  if [ -n "$CHROME" ]; then
    # headless Chrome honours the print stylesheet, which the others approximate
    "$CHROME" --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
      --print-to-pdf="$PDF" "file://$HTML" >/dev/null 2>&1 && [ -s "$PDF" ] && pdf_ok=1
  fi
  if [ "$pdf_ok" = 0 ] && have wkhtmltopdf; then
    wkhtmltopdf --enable-local-file-access -q "$HTML" "$PDF" >/dev/null 2>&1 && [ -s "$PDF" ] && pdf_ok=1
  fi
  if [ "$pdf_ok" = 0 ] && have weasyprint; then
    weasyprint "$HTML" "$PDF" >/dev/null 2>&1 && [ -s "$PDF" ] && pdf_ok=1
  fi
  # A missing PDF converter is a reporting gap, not a failed scan — warn, never
  # change the exit code.
  [ "$pdf_ok" = 1 ] || warn "PDF not generated: install Chrome, wkhtmltopdf, or weasyprint"
fi

# ── summary ──
head2 "Summary"
printf '  %sCRITICAL %s  %sHIGH %s  %sMEDIUM %s  %sLOW %s  (total %s)\n' \
  "$C_R" "$CRIT" "$C_R" "$HIGH" "$C_Y" "$MED" "$C_D" "$LOW" "$TOTAL"
if [ "$ERRORS" -gt 0 ]; then
  printf '  %s⨯ %s pass(es) could not complete — those areas are UNKNOWN, not clean%s\n' "$C_R$C_BOLD" "$ERRORS" "$C_0"
  jq -rs '.[]|select(.status=="error")|"      · \(.pass): \(.detail)"' "$STATUS"
fi
[ "$BASE_N" -gt 0 ] && printf '  %s+ %s accepted via baseline (excluded from the gate)%s\n' "$C_D" "$BASE_N" "$C_0"
[ "$DIFF_N" -gt 0 ] && printf '  %s+ %s pre-existing outside the diff (reported, not gated)%s\n' "$C_D" "$DIFF_N" "$C_0"
say "  report: $C_BOLD$REPORT$C_0"
say "  html:   $C_BOLD$HTML$C_0"
[ "$DO_PDF" = 1 ] && [ -s "$PDF" ] && say "  pdf:    $C_BOLD$PDF$C_0"
say "  sarif:  $C_BOLD$SARIF$C_0"

if [ "$DO_OPEN" = 1 ]; then
  if have open; then open "$HTML" >/dev/null 2>&1
  elif have xdg-open; then xdg-open "$HTML" >/dev/null 2>&1
  else warn "could not open a browser automatically — file://$HTML"; fi
fi

# Fail closed: an incomplete scan is not a pass. Exit 3 is distinct from 1 so CI
# can tell "we found problems" from "we could not look".
case "$VERDICT" in
  INCOMPLETE) bad "INCOMPLETE — $ERRORS pass(es) failed to run (exit 3). Fix the tooling or pass --no-fail-on-error."
              [ "$gate" = 1 ] && bad "also: findings at/above '$FAIL_ON' threshold ($reason)";;
  FAIL)       bad "FAIL — findings at/above '$FAIL_ON' threshold ($reason)";;
  PASS)       [ "$ERRORS" -gt 0 ] && warn "passed threshold, but $ERRORS pass(es) were incomplete (--no-fail-on-error was set)"
              ok "PASS — no findings above '$FAIL_ON' threshold";;
esac
exit "$RC"
