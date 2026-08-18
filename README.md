# VibeCheck 🔍

[![VibeCheck Security](https://github.com/rabbai007/TestAndVibes/actions/workflows/vibecheck.yml/badge.svg?branch=main)](https://github.com/rabbai007/TestAndVibes/actions/workflows/vibecheck.yml)

**Portable, non-destructive security audit for web apps — one command, any stack.**

VibeCheck wraps the best open-source security scanners behind a single script,
auto-detects your stack, and produces a consolidated report plus a CI-friendly
exit code. It's built for the era of AI-assisted ("vibe") coding, where code
ships fast and security regressions slip in quietly.

It runs four **static** passes on your source, and an optional set of **safe,
read-only dynamic** checks against a URL you control:

| Pass | What it checks | Tool(s) |
|------|----------------|---------|
| 🔑 Secrets | Committed / working-tree credentials (verified only) | trufflehog, gitleaks |
| 🧠 SAST | Insecure code patterns (injection, authz, crypto, XSS…) | semgrep |
| 📦 Dependencies | Known CVEs in your lockfiles | trivy, osv-scanner, npm audit |
| 🐳 IaC / Containers | Dockerfile / Terraform / K8s misconfig | trivy config |
| 🌐 Dynamic *(opt-in)* | HTTP security headers, cookie flags, CORS, TLS version + cert expiry | curl, openssl |

> **Not a replacement for a professional penetration test.** This is automated
> baseline hardening + regression prevention. For production systems handling
> real user data, get an independent external pentest too. See *Philosophy*.

---

## It fails closed

A security gate has to distinguish **"nothing found"** from **"nothing looked."**
When a pass cannot complete — no lockfile to scan, a scanner that crashed or
isn't installed, an unreachable URL, an IaC file that won't parse — VibeCheck
reports **ERROR** and exits **3**. It never renders an unscanned area as clean.

```
▶ 3. Dependency vulnerabilities
  ⨯ ERROR: no scannable lockfile for: node — commit a lockfile
    (npm i --package-lock-only) or --skip-deps. Dependencies NOT scanned.

  ⨯ 1 pass(es) could not complete — those areas are UNKNOWN, not clean
  ✗ INCOMPLETE — 1 pass(es) failed to run (exit 3).
```

If a pass genuinely doesn't apply to your repo, skip it **explicitly**
(`--skip-deps`) so the report records the decision. `--no-fail-on-error` exists
for migration, but it reintroduces the failure mode this design prevents.

## Quick start

```bash
# 1. install jq (required) + the underlying scanners
./vibecheck.sh --install

# 2. scan the current directory (static only)
./vibecheck.sh

# 3. scan another app + run the safe dynamic checks against its URL
./vibecheck.sh --dir ../my-app --url https://staging.my-app.com

# 4. use as a CI gate — fail the build on high+ findings
./vibecheck.sh --fail-on high
```

Drop `vibecheck.sh` into any repo (or keep it in one place and point `--dir` at
targets). No config required.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--dir PATH` | `.` | Directory to scan |
| `--url URL` | — | Enable dynamic checks against this URL (implies `--dynamic`) |
| `--all` | — | Static + dynamic |
| `--fail-on LEVEL` | `high` | Exit 1 at/above `never\|low\|medium\|high\|critical\|any` |
| `--no-fail-on-error` | — | Don't exit 3 on an incomplete pass (**unsafe** — see above) |
| `--out DIR` | `vibecheck-report` | Where to write the report + raw tool output |
| `--config PATH` | `./vibecheck.yml` | Config file (see [`config/`](config/)) |
| `--semgrep-config X` | `auto` | Semgrep ruleset; `p/ci` avoids the network |
| `--secrets-strict` | — | Rate unverified secrets high instead of medium |
| `--skip-secrets`/`-sast`/`-deps`/`-iac` | — | Explicitly skip a pass (recorded as *skipped*) |
| `--pdf` | — | Also render `report.pdf` (Chrome / wkhtmltopdf / weasyprint) |
| `--open` | — | Open the HTML report in your browser when done |
| `--diff REF` | — | PR mode: gate only on findings in files changed vs `REF` (implies `--base`) |
| `--base REF` | — | Read config/ignore/baseline from `REF`, not the working tree |
| `--trust-repo-config` | — | Honour in-tree config even with `--base` (**unsafe** on untrusted code) |
| `--baseline PATH` | `./.vibecheck-baseline.json` | Accepted-findings file |
| `--write-baseline` | — | Accept every current finding, then exit |
| `--no-baseline` | — | Ignore the baseline and gate on everything |
| `--install` | — | Install jq + the scanners and exit |
| `--version`, `--help` | — | Version / usage |

**Exit codes:** `0` clean · `1` findings at/above threshold · `2` usage error ·
`3` a pass could not complete (fail-closed).

## Output

A human-readable console summary, plus `vibecheck-report/`:
- `report.md` — per-pass status table + every finding with `file:line`, rule ID,
  and a reference link, grouped by severity
- `report.html` — formatted, self-contained report (print/PDF-ready); `--pdf`
  also writes `report.pdf`
- `vibecheck.sarif` — SARIF 2.1.0 for GitHub Code Scanning or any SARIF viewer
- `findings.json` — machine-readable findings (`active` and `accepted`)
- raw JSON from each scanner (`semgrep.json`, `trivy-deps.json`, …) for triage

Every scanner produces false positives. **Triage before acting** — the report
is a starting point, not a verdict.

## Adopting on an existing codebase

A first scan of a mature repo will surface a lot. Accept the current state as a
baseline, then gate only on what's new:

```bash
./vibecheck.sh --write-baseline     # accept everything found today
./vibecheck.sh --fail-on high       # from now on, only NEW findings fail
```

Commit `.vibecheck-baseline.json` — it's shared team state. Each entry records
when it was accepted and has a `reason` field; fill it in so the next reader
knows why. Entries older than 90 days warn, and entries that no longer match
anything are flagged as prunable (usually meaning the finding was fixed).

Findings in the baseline stay **visible in every report** — they're accepted,
not hidden. Two things the baseline deliberately cannot do: suppress an
**ERROR** (you can accept a known risk, but never "we didn't scan this"), or
survive a change to the finding itself. Identity excludes line numbers, so
unrelated edits above a finding won't resurrect it.

**One entry can cover several occurrences.** Identity is
`tool | rule | file | title` — so when a scanner emits the *same message* for
every hit of a rule in a file (semgrep does this routinely), all of those hits
share one fingerprint and one entry accepts them together. That is usually what
you want, but it means a **new** occurrence of an already-accepted rule in an
already-accepted file would otherwise be suppressed silently.

To close that, each entry records how many findings it covered when accepted,
and VibeCheck warns when that count grows:

```
! baseline entry 1a7b5fcda18b now suppresses 6 finding(s), was 5 when accepted
      · ci/github-actions.yml:55
```

Treat that as a prompt to look: either the new occurrence is covered by the same
decision (re-run `--write-baseline` to update the count) or it isn't (fix it, or
split the entry by making the finding distinct).

### Configuration is not trusted from the code being scanned

`vibecheck.yml`, `.vibecheckignore` and `.vibecheck-baseline.json` decide what
gets scanned and what fails the build. On a pull request those files are written
by the change under test — so read from the working tree, they let a change
suppress its own findings.

`--base REF` (implied by `--diff`) reads all three from a trusted ref instead:

```bash
./vibecheck.sh --diff origin/main --fail-on high   # config comes from origin/main
```

Two further guards apply even without a base ref:

- A config file cannot set **`fail_on: never`** unless `--fail-on never` is also
  passed on the command line. A total gate bypass has to be typed by a human.
- If **no pass examined anything**, that is an ERROR, not a clean exit 0 —
  however the scan came to be empty.

`--trust-repo-config` restores the old behaviour. Only use it on code you
control.

### Gating pull requests on what they introduce

`--diff` scopes the gate to files the change touched, so a PR fails for what it
adds rather than what it inherited:

```bash
./vibecheck.sh --diff origin/main --fail-on high    # in PR CI
./vibecheck.sh --fail-on high                       # full scan on your default branch
```

Findings outside the diff are still reported, just not gated. Dynamic checks
always count — they describe the running application, not a file in the diff.

**Run both.** `--diff` is a PR gate, not a replacement for a full scan; on its
own it would let pre-existing issues accumulate unexamined. If the ref is
missing or the target isn't a git repo, VibeCheck exits 3 rather than quietly
scoping to nothing — in CI, remember `fetch-depth: 0` so the base ref exists.

## Configuration

Optional. Copy [`config/vibecheck.example.yml`](config/vibecheck.example.yml) to
`vibecheck.yml` (auto-detected) and/or
[`.vibecheckignore.example`](.vibecheckignore.example) to `.vibecheckignore`.
CLI flags override the config file. Ignore patterns are passed through to
semgrep, trivy, and trufflehog.

## CI integration

Snippets in [`ci/`](ci/):
- **GitLab CI** — [`ci/gitlab-ci.snippet.yml`](ci/gitlab-ci.snippet.yml)
- **GitHub Actions** — [`ci/github-actions.yml`](ci/github-actions.yml) (uploads
  SARIF to the Security tab; needs `security-events: write`)

Recommended rollout: run secret + dependency scanning as **blocking** from day
one (near-zero false positives), and SAST as **report-first** until you've
triaged the initial baseline — then flip it to blocking.

Treat an **exit 3 as a real failure**, not noise: it means an area wasn't
scanned. The usual causes are an uncommitted lockfile or a scanner missing from
the runner image — both worth fixing rather than suppressing.

## Hardening checklist

[`hardening/CHECKLIST.md`](hardening/CHECKLIST.md) is a manual review companion —
the classes of issue automated tools miss (business-logic authz, multi-tenant
isolation / IDOR, session handling, file-upload safety). It's organized by
OWASP theme and is the highest-value 30 minutes you'll spend on a new app.

## Requirements

Bash (macOS/Linux) and **[`jq`](https://jqlang.github.io/jq/)** (required — all
scanner output is parsed as JSON), plus the scanners you want active:
[semgrep](https://semgrep.dev) · [trivy](https://trivy.dev) ·
[grype](https://github.com/anchore/grype) ·
[trufflehog](https://github.com/trufflesecurity/trufflehog) ·
[gitleaks](https://github.com/gitleaks/gitleaks) · `curl`, `openssl` (usually preinstalled).
`--install` sets these up via Homebrew + pipx.

A scanner that is missing makes its pass an **ERROR**, not a silent skip — use
`--skip-*` if you don't want that pass. Note `--semgrep-config auto` fetches
rules from semgrep.dev and needs network access; use `--semgrep-config p/ci` on
air-gapped runners.

## Philosophy

Automated scanning catches the **known** and the **mechanical**: leaked secrets,
CVE'd dependencies, insecure code patterns, missing headers. It is fast, cheap,
and belongs in CI so regressions can't merge silently.

It does **not** catch **business-logic** flaws — the ones that actually breach
real apps: broken access control, multi-tenant data leaks (IDOR), auth bypasses,
insecure workflows. Those need a human who understands the app's intent. That's
what the hardening checklist and a real pentest are for.

Use all three layers: **VibeCheck (automated, in CI)** + **the checklist
(manual, per feature)** + **an independent pentest (periodic, for attestation)**.

## Prior art & credit

Inspired in part by [benavlabs/vibe-check](https://github.com/benavlabs/vibe-check),
which takes a complementary *checklist + AI-rules* approach. VibeCheck focuses on
the **executable automation** layer — actually running the scanners and gating CI.
Use both.

## License

MIT — see [LICENSE](LICENSE). Provided as-is; **only scan systems you own or are
authorized to test.**
