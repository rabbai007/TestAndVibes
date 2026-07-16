# VibeCheck 🔍

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
| 🌐 Dynamic *(opt-in)* | HTTP security headers, cookie flags, CORS, TLS version | curl, openssl |

> **Not a replacement for a professional penetration test.** This is automated
> baseline hardening + regression prevention. For production systems handling
> real user data, get an independent external pentest too. See *Philosophy*.

---

## Quick start

```bash
# 1. install the underlying scanners (Homebrew + pipx; or install manually)
./vibecheck.sh --install

# 2. scan the current directory (static only)
./vibecheck.sh

# 3. scan another app + run the safe dynamic checks against its URL
./vibecheck.sh --dir ../my-app --url https://staging.my-app.com

# 4. use as a CI gate — fail the build on high+ findings
./vibecheck.sh --fail-on high
```

Drop `vibecheck.sh` into any repo (or keep it in one place and point `--dir` at
targets). No config required; it degrades gracefully when a scanner is missing
(prints an install hint and skips that pass).

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--dir PATH` | `.` | Directory to scan |
| `--url URL` | — | Enable dynamic checks against this URL (implies `--dynamic`) |
| `--all` | — | Static + dynamic |
| `--fail-on LEVEL` | `high` | Exit non-zero at/above `never\|low\|medium\|high\|critical\|any` |
| `--out DIR` | `vibecheck-report` | Where to write the report + raw tool output |
| `--install` | — | Install the scanners and exit |
| `--help` | — | Usage |

**Exit codes:** `0` clean at/under threshold · `1` findings over threshold · `2` error.

## Output

A human-readable console summary, plus `vibecheck-report/`:
- `report.md` — consolidated findings + a severity summary table
- raw JSON from each scanner (`semgrep.json`, `trivy-deps.json`, …) for triage

Every scanner produces false positives. **Triage before acting** — the report
is a starting point, not a verdict.

## CI integration

Snippets in [`ci/`](ci/):
- **GitLab CI** — [`ci/gitlab-ci.snippet.yml`](ci/gitlab-ci.snippet.yml)
- **GitHub Actions** — [`ci/github-actions.yml`](ci/github-actions.yml)

Recommended rollout: run secret + dependency scanning as **blocking** from day
one (near-zero false positives), and SAST as **report-first** until you've
triaged the initial baseline — then flip it to blocking.

## Hardening checklist

[`hardening/CHECKLIST.md`](hardening/CHECKLIST.md) is a manual review companion —
the classes of issue automated tools miss (business-logic authz, multi-tenant
isolation / IDOR, session handling, file-upload safety). It's organized by
OWASP theme and is the highest-value 30 minutes you'll spend on a new app.

## Requirements

Bash (macOS/Linux), plus whichever scanners you want active:
[semgrep](https://semgrep.dev) · [trivy](https://trivy.dev) ·
[grype](https://github.com/anchore/grype) ·
[trufflehog](https://github.com/trufflesecurity/trufflehog) ·
[gitleaks](https://github.com/gitleaks/gitleaks) · `curl`, `openssl` (usually preinstalled).
`--install` sets up the first five via Homebrew + pipx.

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
