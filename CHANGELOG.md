# Changelog

All notable changes to **VibeCheck** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 0.3.0 in progress

### Added

- **Baseline of accepted findings** — adopt VibeCheck on an existing codebase
  without triaging everything at once. `--write-baseline` accepts every current
  finding; subsequent runs gate only on what is new. `--baseline PATH` selects a
  file (default `./.vibecheck-baseline.json`), `--no-baseline` ignores it.
  - Identity is `sha256(tool|rule|file|title)` and deliberately **excludes the
    line number**, which shifts whenever anything above a finding is edited —
    including it would resurrect every accepted entry on the next commit. Also
    emitted as SARIF `partialFingerprints`.
  - **An ERROR state is not baselineable.** Accepting a finding is a judgement
    about known risk; accepting "this area was never scanned" would reintroduce
    the fail-open behaviour 0.2.0 removed.
  - Accepted findings stay **visible** — listed in the console, both reports, and
    counted in the summary — but excluded from the gate and from SARIF.
  - Entries record an `added` date and a `reason` field for a human to fill in.
    Entries older than 90 days warn but still suppress. Re-running
    `--write-baseline` preserves existing dates and reasons; entries matching
    nothing are reported as prunable.
- **HTML and PDF reports** — `report.html` is generated on every run;
  `--pdf` renders `report.pdf` (headless Chrome, falling back to wkhtmltopdf then
  weasyprint) and `--open` opens the report in your browser. The HTML embeds all
  styling and references nothing external, so it survives being emailed.
  - Severity is a row of stat tiles rather than a chart, each pairing colour with
    an icon and a label so colour never carries meaning alone.
  - The document states its own limits: the verdict leads, a coverage table shows
    which passes ran and which errored, and a closing scope block states this is
    an automated scan rather than a penetration test.

### Fixed

- `ci/github-actions.yml` referenced `aquasecurity/setup-trivy@v0.2.3`, which does
  not exist — copying the template produced an immediate CI failure. Now v0.3.1.
- `.gitignore` pattern `vibecheck.yml` was unanchored and matched at any depth,
  silently excluding `.github/workflows/vibecheck.yml` from commits.

### Added (CI)

- `.github/workflows/vibecheck.yml` — the repository is now gated by its own tool,
  with every action pinned to a commit SHA.

## [0.2.0] — 2026-08-11

**Correctness release. 0.1.0 could report a vulnerable app as clean — upgrade.**

> ⚠️ **Breaking:** VibeCheck now **fails closed**. A pass that cannot complete
> (missing lockfile, crashed scanner, unreachable URL, absent tool) exits **3**
> instead of silently passing. Pipelines that were green on 0.1.0 may now fail —
> in most cases because they were never actually scanning that area. Skip a pass
> explicitly (`--skip-deps`) rather than reaching for `--no-fail-on-error`.

### Fixed — false "clean" results

- **Dependency scan reported 0 CVEs when no lockfile was present.** Trivy emits
  JSON with no `Results` key for an unscannable manifest; 0.1.0 grepped it for
  severity strings, found none, printed `✓ 0 HIGH/CRITICAL`, and set an internal
  flag that suppressed the `npm audit` fallback. Verified on a fixture pinning
  `lodash@4.17.4` + `minimist@0.0.8`: 0.1.0 → 0 findings; 0.2.0 → ERROR with
  remediation, and 2 CRITICAL + 4 HIGH once a lockfile exists.
- **Dynamic header checks read the wrong HTTP response.** `curl -sSL -D -`
  concatenates the headers of *every* redirect hop, so headers set on an
  HTTP→HTTPS redirect (typical of a CDN or load balancer) made the application
  response look compliant. Only the final response is evaluated now, and the
  redirect count is disclosed. Verified: a 301 carrying all six headers plus a
  200 carrying none reported all six as *present* on 0.1.0.
- **Cookie flags passed if *any* cookie was compliant.** A `session` cookie with
  no `HttpOnly` hid behind a compliant tracking cookie. Cookies are now checked
  individually for `HttpOnly`, `Secure`, and `SameSite`, and session-like names
  (`sess|sid|auth|token|jwt|login|remember|csrf`) are rated high.
- **An invalid `--fail-on` value silently disabled the gate.** `--fail-on typo`
  matched no `case` branch and exited 0 — a config typo meant a permanently
  green pipeline. The value is now validated (exit 2).
- **A crashed scanner was indistinguishable from a clean scan.** `if [ -f json ]`
  with no `else` meant an offline, rate-limited, or OOM-killed semgrep/trivy
  produced no output and no findings. Every pass now reports an explicit
  `ok | findings | skipped | error` status.
- **Unparsed IaC files were reported as clean.** trivy logs a Terraform/YAML
  parser error to stderr and still prints "0 misconfigurations"; stderr is now
  inspected and a parse failure is an ERROR.
- **Terraform was only detected at the repo root.** `ls "$TARGET"/*.tf` missed
  `infra/`, `terraform/`, and `modules/`, skipping the entire IaC pass for most
  real layouts. Detection is recursive (and now covers Helm and k8s manifests).
- **`gitleaks` treated any non-zero exit as "secrets found"** — including "not a
  git repo". Exit 1 (leaks) is now distinguished from >1 (real error), and
  non-git targets use `--no-git`.
- **`--only-verified` silently dropped most real secrets.** It reports only
  credentials trufflehog can authenticate live, excluding DB passwords, private
  keys, and internal tokens. Both classes are now reported: verified as
  critical, unverified as medium (`--secrets-strict` raises to high).
- **`--help` printed source code.** It `sed`-extracted lines 3–30 of the script
  and overran the header comment.

### Added

- **SARIF 2.1.0 output** (`vibecheck-report/vibecheck.sarif`) with
  `security-severity` properties and fully declared rules — uploadable to GitHub
  Code Scanning (`github/codeql-action/upload-sarif`) or any SARIF viewer. CI
  snippets updated to upload it on every run, including failures.
- **Per-finding detail in `report.md`** — tool, rule ID, `file:line`, message,
  and a reference link, grouped by severity. 0.1.0 reported only counts.
- **`findings.json`** — machine-readable findings for custom tooling.
- **Per-pass status table** in the report, so an empty section is no longer
  ambiguous between "clean" and "never ran".
- **Exit code 3** for an incomplete scan, distinct from 1 (findings found), so
  CI can tell "we found problems" from "we could not look".
- `--skip-secrets`, `--skip-sast`, `--skip-deps`, `--skip-iac` — explicit,
  audited opt-outs that are recorded as *skipped* rather than passing silently.
- `--version`, `--no-fail-on-error`, `--secrets-strict`, `--semgrep-config`
  (use `p/ci` for offline-safe runs; `auto` requires network access).
- **`vibecheck.yml` is now actually read** (`--config`, or auto-detected in the
  working directory). 0.1.0 shipped and `.gitignore`'d an example config that no
  code path ever opened.
- **`.vibecheckignore` is now actually honored** — exclusions are passed to
  semgrep, trivy, and trufflehog. Also previously unimplemented.
- **`grype` is now actually invoked** as the dependency-scan fallback. 0.1.0
  installed it via `--install` and listed it in the README without ever calling it.
- **Stack detection** for Java (Maven/Gradle), .NET, Elixir, and Helm; recursive
  Terraform discovery.
- **Dynamic checks:** HSTS `max-age` adequacy, CORS wildcard escalated to high
  when combined with `Allow-Credentials: true`, active TLS 1.0/1.1 *acceptance*
  probing (0.1.0 only inspected what OpenSSL happened to negotiate, so a server
  still accepting TLS 1.0 was reported "modern"), certificate expiry, and a
  plain-HTTP warning.

### Changed

- **`jq` is now a hard requirement.** All scanner output is parsed as JSON
  instead of grepped for quoted severity strings — the fragility behind several
  of the false-clean results above. `--install` installs it.
- Findings are stored once (JSONL) and every output — console, `report.md`,
  SARIF, `findings.json`, and the gate — is derived from that single source.
  This also removes 0.1.0's `for i in $(seq 1 "$e"); do add high; done`
  severity-inflation loop.
- Dependency and IaC scans now include MEDIUM severity (was HIGH/CRITICAL only).
- CVEs are deduplicated by ID + package version; the secret scan makes one pass
  over the tree instead of two.
- `--fail-on low` and `--fail-on any` are no longer identical: `any` includes
  informational findings.

## [0.1.0] — 2026-07-16

Initial public release — portable, non-destructive security auditing for web apps.
One command wraps best-in-class OSS scanners, auto-detects the stack, and emits a
consolidated report plus a CI-friendly exit code.

### Added

- **`vibecheck.sh` orchestrator** — stack auto-detection
  (node / python / go / rust / php / ruby / docker / terraform), consolidated
  `report.md` + raw per-scanner JSON, `--fail-on` gate for CI, and graceful
  degradation (a missing scanner is skipped with an install hint).
- **Static passes:**
  - 🔑 Secrets — committed & working-tree credentials, verified-only (trufflehog / gitleaks)
  - 🧠 SAST — insecure code patterns: injection, authz, crypto, XSS (semgrep)
  - 📦 Dependencies — known CVEs in lockfiles (trivy / osv-scanner / npm audit)
  - 🐳 IaC & containers — Dockerfile / Terraform / K8s misconfig (trivy config)
- **Dynamic checks** (opt-in, `--url`) — HTTP security headers, cookie flags,
  CORS, and TLS version. Read-only: a GET + TLS handshake, no payloads.
- **Three-layer toolkit** — `AGENTS.md` (prevent: AI-assistant security rules),
  `vibecheck.sh` + `ci/` (detect: automated, CI-gated),
  `hardening/CHECKLIST.md` (verify: manual, business-logic review).
- **CI snippets** — ready-to-use GitHub Actions and GitLab CI configurations,
  installing scanners via pinned releases / official setup actions (no `curl | sh`).
- **Supporting files** — `--install` helper (Homebrew + pipx),
  `config/vibecheck.example.yml`, `.vibecheckignore.example`, MIT `LICENSE`.

### Notes

- This is automated baseline hardening + regression prevention — **not** a
  substitute for an independent penetration test. Scanners produce false
  positives; triage before acting.
- Complementary to [benavlabs/vibe-check](https://github.com/benavlabs/vibe-check)
  (a checklist + AI-rules approach); VibeCheck adds the executable automation layer.

[Unreleased]: https://github.com/rabbai007/TestAndVibes/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rabbai007/TestAndVibes/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rabbai007/TestAndVibes/releases/tag/v0.1.0
