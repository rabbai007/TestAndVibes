# VibeCheck 🔍

[![VibeCheck Security](https://github.com/rabbai007/TestAndVibes/actions/workflows/vibecheck.yml/badge.svg?branch=main)](https://github.com/rabbai007/TestAndVibes/actions/workflows/vibecheck.yml)

**Portable, non-destructive security audit for web apps — one command, any stack.**

VibeCheck wraps the best open-source security scanners behind a single script,
auto-detects your stack, and produces a consolidated report plus a CI-friendly
exit code. It's built for the era of AI-assisted ("vibe") coding, where code
ships fast and security regressions slip in quietly.

It runs four **static** passes on your source, an optional set of **safe,
read-only dynamic** checks against a URL you control, and an optional
**adversarial review** that reasons about the code:

| Pass | What it checks | Tool(s) |
|------|----------------|---------|
| 🔑 Secrets | Committed / working-tree credentials (verified only) | trufflehog, gitleaks |
| 🧠 SAST | Insecure code patterns (injection, authz, crypto, XSS…) **+ AI/LLM (OWASP-LLM), SSRF, resource-exhaustion** | semgrep + [`rules/`](rules/) |
| 📦 Dependencies | Known CVEs in your lockfiles (all sources run, results merged) **+ CISA KEV: actively exploited CVEs raised to critical** | trivy + osv-scanner + npm audit + grype + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| 🐳 IaC / Containers | Dockerfile / Terraform / K8s misconfig | trivy config |
| ⚙️ CI/CD | GitHub Actions: script injection, fork-code triggers, unpinned actions/tools, over-broad tokens, credential persistence | [zizmor](https://docs.zizmor.sh) |
| 🖼️ Images *(opt-in)* | Built container images: OS + package CVEs (with KEV/EPSS), secrets in layers, end-of-life base OS | trivy image |
| 🌐 Dynamic *(opt-in)* | HTTP security headers, cookie flags, CORS, TLS version + cert expiry | curl, openssl |
| 🕷️ Deep DAST *(opt-in, `--dast`)* | Every TLS protocol/cipher and known TLS attack; crawl + passive web-app rules; exposed files, panels and misconfigurations | testssl.sh, ZAP baseline, nuclei |
| 🧭 Review *(default; needs a provider)* | Access control, tenant isolation, lifecycle, races, missing controls, prompt injection | an LLM |

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
| `--dast` | — | Deeper, still non-destructive scan of `--url`: testssl.sh + ZAP baseline + nuclei (safe templates). Native tools, else pinned Docker images |
| `--image REF` | — | Scan a built container image (repeatable): CVEs with KEV/EPSS, secrets in layers, end-of-life base OS |
| `--fail-on LEVEL` | `high` | Exit 1 at/above `never\|low\|medium\|high\|critical\|any` |
| `--no-fail-on-error` | — | Don't exit 3 on an incomplete pass (**unsafe** — see above) |
| `--out DIR` | `vibecheck-report` | Where to write the report + raw tool output |
| `--config PATH` | `./vibecheck.yml` | Config file (see [`config/`](config/)) |
| `--semgrep-config X` | `auto` | Semgrep ruleset; `p/ci` avoids the network |
| `--secrets-strict` | — | Rate unverified secrets high instead of medium |
| `--skip-secrets`/`-sast`/`-deps`/`-iac` | — | Explicitly skip a pass (recorded as *skipped*) |
| `--kev` | **on** | Match dependency CVEs against CISA KEV. On by default (warns if the feed is unreachable); passing `--kev` makes an unreachable feed an **ERROR** |
| `--no-kev` | — | Skip the CISA KEV check |
| `--kev-file PATH` | — | Use a local copy of the KEV JSON feed (air-gapped CI; implies `--kev`) |
| `--epss` | **on** | Annotate dependency CVEs with their FIRST EPSS exploit probability. On by default (warns if the API is unreachable); with `--epss` that is an ERROR. Never changes severity |
| `--no-epss` | — | Skip the EPSS lookup |
| `--epss-file PATH` | — | Use a local copy of the daily EPSS CSV (`.csv`/`.csv.gz`; implies `--epss`) |
| `--licenses` | — | Check dependency licences from the lockfiles (needs osv-scanner + network) |
| `--license-allow LIST` | — | Allowed SPDX ids, comma-separated; anything else is high (implies `--licenses`) |
| `--sbom` | — | Write a CycloneDX SBOM (`sbom.cdx.json`, plus one per `--image`) |
| `--ci-audit` | **on** | Audit GitHub Actions workflows with zizmor. On when workflows exist (missing zizmor warns); with `--ci-audit` a missing zizmor is an ERROR |
| `--no-ci-audit` | — | Skip the CI/CD workflow audit |
| `--review` | **on** | Adversarial reasoning pass (report-only). Runs by default when a provider exists; **skips** if none. |
| `--no-review` | — | Turn the review pass off |
| `--fail-on-review` | — | Let surviving review findings affect the exit code |
| `--review-provider` | `auto` | `auto` \| `cmd` \| `anthropic` \| `claude` \| `codex` \| `gemini-api` \| `gemini` — pin the review's model provider (see *Providers*) |
| `--review-model` | provider default | Model for the review pass. Unset = the CLI's own default; the Anthropic HTTP API defaults to `claude-opus-5-5` |
| `--review-effort` | `high` | `low\|medium\|high\|xhigh\|max` |
| `--review-budget` | `400000` | Max bytes of source sent for review (~100k tokens). Files that do not fit are listed and the review is marked **PARTIAL** — never silently dropped |
| `--review-skeptics` | `2` | Independent refutation attempts per finding |
| `--review-cmd CMD` | — | Provider override: prompt on stdin, text on stdout |
| `--mcp TARGET` | — | Probe a running MCP server (read-only): URL or command to spawn |
| `--mcp-timeout N` | `20` | MCP handshake timeout (seconds) |
| `--mcp-header H` | — | One HTTP header for an authed MCP endpoint |
| `--pdf` | **on** | Render `report.pdf` (Chrome / wkhtmltopdf / weasyprint); warns if none present |
| `--no-pdf` | — | Skip the PDF render |
| `--exclude PATH` | — | Exclude a path from scanning (repeatable; operator-trusted, applies under `--base`) |
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

## Dependency scanning uses every source, not the first one it finds

trivy, osv-scanner, npm audit and grype draw on **different advisory databases**,
so whichever one you happen to have installed changes what "0 CVEs" means. All
available sources now run and their results are merged.

Findings record which sources corroborated them:

```
medium  CVE-2018-3721  lodash@4.17.4  [osv-scanner, npm-audit, grype]
```

That one is real: **trivy alone misses it.** OSV also supplies the CVE↔GHSA alias
table, which is what lets a CVE from trivy and a GHSA from npm audit be
recognised as the same vulnerability rather than counted twice. Which scanners
corroborated a finding is deliberately *not* part of its fingerprint, so
installing another tool never invalidates your baseline.

## Actively exploited: the CISA KEV check

The advisory databases say a CVE **exists**. CISA's
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog says it is **being exploited in the wild** — the strongest prioritisation
signal there is, and the list US federal agencies must patch against a deadline.

After the dependency pass, every CVE (and every CVE alias of a GHSA id, via
OSV's alias table and grype's related-vulnerability data) is matched against the
catalog, fetched fresh from cisa.gov on each run. A match is **raised to
critical** whatever its CVSS, and labelled with CISA's due date and whether it is
known to be used in ransomware campaigns:

```
▶ 3b. CISA Known Exploited Vulnerabilities
  ✗ CISA KEV: 1 dependency CVE(s) are being actively exploited in the wild - raised to critical
      · CVE-2020-11023  jquery@3.4.1: ...  (CISA due 2025-02-13, ransomware: Unknown)
```

That one is real, and it is the point: all four scanners rate it **medium**, so
without KEV it passes a `--fail-on high` gate.

- `findings.json` keeps `severity_original` and a `kev` object (`cve`, `dateAdded`,
  `dueDate`, `ransomware`, `name`); the report records the catalog version used.
- **The baseline cannot quietly accept an exploited CVE.** An entry accepted
  *before* the CVE was KEV-listed stops suppressing it — accepting a medium is not
  accepting an actively exploited bug. Re-accept it deliberately with
  `--write-baseline`, which records `"kev": true`.
- **Unreachable feed:** by default a warning, recorded in the report as *KEV NOT
  checked* (a cisa.gov outage should not redden every build). Pass `--kev` to make
  it an ERROR (exit 3). On air-gapped runners, mirror the
  [JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
  and pass `--kev-file`; a copy older than 14 days warns.
- **Scope, honestly:** KEV is weighted toward vendor products (VPNs, firewalls,
  Windows), so hits on application dependencies are rare — but when one fires,
  it is the finding to fix today. Matching is by CVE id: an advisory with no CVE
  alias cannot match.

### Likely to be exploited: EPSS

KEV says a CVE is exploited **now**; [FIRST EPSS](https://www.first.org/epss/)
estimates the probability it will be exploited **in the next 30 days**. That is
the answer to "which of these 40 mediums first?". Each dependency CVE (and its
CVE aliases) gets an `epss` object (`score`, `percentile`, `date`) in
`findings.json`, and the score in its title, e.g. `[EPSS 84.9%, percentile 99.7]`. The
five highest are listed in the console.

- **Annotation only.** EPSS is a likelihood, not an impact: it never changes a
  severity, the gate, or a fingerprint. Use it to order the work.
- **Unscored is unknown, not 0%.** A CVE FIRST has not scored (or an advisory with
  no CVE id) gets no annotation.
- **Same failure contract as KEV:** on by default, an unreachable API warns and is
  recorded as *EPSS NOT checked*; `--epss` makes it an ERROR. Offline, download the
  [daily CSV](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz) and pass
  `--epss-file` (`.csv` or `.csv.gz`); a copy older than 14 days warns.

## Container images: what was built, not just the Dockerfile

The IaC pass reads the Dockerfile; `--image` scans the image it produced:

```bash
docker build -t myapp:ci . && ./vibecheck.sh --image myapp:ci
```

- **OS and language-package CVEs** in every layer, base image included. They go
  through CISA KEV and EPSS like dependency CVEs (base images are where most
  KEV-listed CVEs, such as OpenSSL or glibc, actually sit), even with `--skip-deps`.
- **Secrets baked into a layer.** Deleting a file in a later layer does not remove
  it from the image: rotate it.
- **End-of-life base OS** (high): it no longer gets security fixes, so "0 CVEs" on
  it means nothing.

Repeat `--image` for several images. Each image that cannot be scanned (bad
reference, no registry access, no daemon) is an **ERROR (exit 3)**. Image
findings have `file: "image:REF"` and always stay in scope under `--diff`.

## CI/CD workflows

The pipeline holds the deploy keys, and none of its common flaws are visible to SAST
on the app: a `${{ github.event.pull_request.title }}` expanded into a `run:` script,
a `pull_request_target` job that checks out fork code, a mutable action tag, a
workflow-wide `write` token, `actions/checkout` leaving the token on disk. Pass 4b
runs [zizmor](https://docs.zizmor.sh) on every `.github/workflows/*.yml` and
`action.yml` (respecting excludes); findings land on the workflow file and line.

- **On by default** when workflows exist. zizmor is new in 0.11, so a missing
  zizmor **warns** and is recorded as *NOT audited* instead of failing an upgrade;
  `--ci-audit` makes it an ERROR. `pipx install zizmor` (or `--install`).
- **Offline unless a token is set.** With `GH_TOKEN` (or `GITHUB_TOKEN`) zizmor also
  runs its online audits (known-vulnerable actions, impostor commits). In Actions,
  pass `GH_TOKEN: ${{ github.token }}`; read-only is enough.
- Informational findings are dropped; low-confidence ones say so in the title.

This repository's own workflows were fixed for what it found (token persistence,
workflow-wide `security-events: write`, an unpinned trivy).

## Deep DAST: crawl and probe the running app

```bash
./vibecheck.sh --url https://staging.my-app.com --dast
```

Pass 5 checks one response. `--dast` does what a pentest starts with: crawl the
app and probe what it exposes. It stays **non-destructive**; only scan targets you
own or are authorised to test.

| Tool | What it adds | Kept safe by |
|---|---|---|
| [testssl.sh](https://testssl.sh) | Every protocol and cipher, certificate chain/SAN/revocation, known TLS attacks (LUCKY13, ROBOT, Heartbleed...) | Handshakes only |
| [ZAP](https://www.zaproxy.org/docs/docker/baseline-scan/) baseline | Spiders the app for a minute and applies ZAP's passive rules to every page: CSRF tokens, information leaks, insecure forms... | No active scan, so no attack payloads |
| [nuclei](https://github.com/projectdiscovery/nuclei) | ~6,000 templates for exposed `.git`/`.env`/backups, admin panels, misconfigurations, known CVEs | `intrusive`, `dos`, `fuzz`, `brute-force` and `default-login` templates excluded; no out-of-band callbacks (`-ni`), so target data is not sent to a third-party service; rate-limited |

Each tool runs natively if installed, otherwise from its **Docker image, pinned by
digest** (override with `VIBECHECK_IMG_TESTSSL` / `_ZAP` / `_NUCLEI`). A
`localhost` target is mapped for the container (`host.docker.internal` on macOS,
`--network host` on Linux). The nuclei template release is recorded in the report.

Fail-closed, as everywhere:

- A tool that is missing (and no Docker), or cannot complete, is an **ERROR**.
- **The target must still be answering when nuclei finishes.** nuclei's own
  "skip unresponsive hosts" logic was turned off (`-nmhe`): a few malformed
  templates trip it against a healthy server, after which nuclei silently skips
  the remaining thousands and reports nothing. If the target did go down, the
  findings so far are kept and the pass is an ERROR, never "0 findings".
- Findings already reported by pass 5 (headers, cookies, HSTS, legacy TLS, expiry)
  are not counted twice.

A full run takes about 5 minutes. Active scanning (ZAP's attack mode) is
deliberately not offered: it sends payloads that can change data.

## Licences and the SBOM

**`--licenses`** classifies every dependency's licence, read from the lockfiles
(osv-scanner with deps.dev data, so no `npm install` is needed; it needs network).
Default policy:

| Severity | Licences | Why |
|---|---|---|
| high | AGPL, SSPL, BUSL, Elastic-2.0, Commons Clause, CC-BY-NC, PolyForm | Network copyleft or source-available: running it in a hosted service can oblige you to publish your source, or is not permitted |
| medium | GPL, EUPL, OSL and other strong copyleft | Distributing your software can oblige you to release its source |
| medium | `non-standard`, no licence | Custom terms, or all rights reserved: read them |
| — | MIT, Apache, BSD, ISC, MPL, LGPL, EPL and other permissive / weak copyleft | |

An `OR` expression passes if any side is acceptable (`MIT OR GPL-3.0` passes).
**`--license-allow MIT,Apache-2.0,...`** replaces the policy with your own
allowlist: anything else is high. Findings are filed against the lockfile, so
`--diff` and the baseline work as usual. This is engineering triage, not legal
advice.

**`--sbom`** writes `sbom.cdx.json` (CycloneDX) for the source tree, plus
`sbom-image-N.cdx.json` for each `--image`. A failed SBOM is an ERROR.

## The adversarial review pass

Everything else in VibeCheck matches patterns. `--review` reasons instead: it is
given the code and asked who controls each input, where the trust boundary sits,
and which required control is missing.

```bash
./vibecheck.sh --review                    # report-only
./vibecheck.sh --review --fail-on-review   # let it gate
```

On a three-file fixture — a session helper exposing `orgId`, a route that never
checks it, and a data layer documented as unscoped — the pattern passes report
**0 findings, exit 0, clean.** The review pass reports the critical cross-tenant
refund: any authenticated user can refund another tenant's invoice. No single line
is wrong; the bug is the *relationship* between three files, which is why no rule
can express it.

**It is report-only by default, deliberately.** Model output is probabilistic,
and one false positive that reddens a build costs more trust than a missed
finding ever does. Findings have to earn the gate.

Every candidate is put to independent **refutation** — skeptics asked to argue
*against* it, defaulting to refuted. A majority refuting drops it. Findings that
survive are reported with their reasoning; refuted ones are counted, not shown.

**Providers.** The review works with whichever AI tool you already use. With
`--review-provider auto` (the default) the first available one wins:

| Order | Provider | Needs | Model when `--review-model` is unset | Effort |
|---|---|---|---|---|
| 1 | `cmd` | `--review-cmd CMD` (prompt on stdin, text on stdout — self-hosted, Ollama, anything) | yours | yours |
| 2 | `anthropic` | `ANTHROPIC_API_KEY` (HTTP API, with retries) | `claude-opus-5-5` | `output_config.effort` |
| 3 | `claude` | Claude Code CLI, signed in | the CLI's default | `--effort` |
| 4 | `codex` | OpenAI Codex CLI, signed in (`codex login`) | the CLI's default | `model_reasoning_effort` |
| 5 | `gemini-api` | Google's [Gemini API CLI](https://github.com/google-gemini/gemini-api-cli) + `GEMINI_API_KEY` | the CLI's default | not supported (ignored, noted) |
| 6 | `gemini` | Gemini CLI — **Gemini Code Assist Standard/Enterprise only** since 2026-06-18 | the CLI's default | not supported (ignored, noted) |

**Using Gemini:** use `gemini-api` with a `GEMINI_API_KEY`. Since June 18, 2026,
free and Google AI Pro/Ultra accounts can no longer use the Gemini CLI (they moved
to the Antigravity CLI, `agy`), and `gemini-api` is the better fit anyway: a
stateless API call with no agent and no tools. **`agy` is not supported as a
provider:** headless `agy` takes the prompt only as a command-line argument
(`-p`), which Linux caps at 128 KB per argument — smaller than a typical review
context — and it has no documented way to disable its tools, only a soft-deny of
actions that need approval.

Pin one with `--review-provider codex` (a pinned provider that is missing is an
ERROR — it never silently falls back to another), and pick a model with
`--review-model`, e.g. `--review-provider gemini --review-model gemini-2.5-pro`.

**AI CLIs run locked down.** They are agents, and the code under review may be
hostile: a prompt injection in a scanned file could otherwise steer the CLI
into reading secrets or running commands. Each one runs from an **empty scratch
directory** with the strictest mode it has — `claude -p --tools ""
--strict-mcp-config`, `codex exec --sandbox read-only --ephemeral`, `gemini
--skip-trust --approval-mode plan` (headless Gemini also denies anything needing
approval; `--skip-trust` stops it silently downgrading `plan` in an untrusted
folder, and is safe because that folder is the empty scratch dir — if Gemini
still reports a downgrade, the review is discarded and the pass fails closed);
`gemini-api` has no tools to begin with. The
prompt carries all the code the review needs, so nothing is lost.

The review runs **by default** when a provider is present; with
no provider it **skips gracefully** (the rest of the scan still runs, so a
provider-less CI job is not reddened). An *explicit* `--review` with no provider
is an **ERROR (exit 3)** — never a quiet "reviewed, found nothing".

Transient failures are retried with backoff on every provider — over the HTTP
API (network errors, 408, 429, 5xx including 529 overloaded; honouring
`Retry-After`) and on the CLIs (5xx, 429, "high demand", overloaded, rate limits,
timeouts) — 3 attempts by default, `VIBECHECK_REVIEW_RETRIES=N` to change it. Anything else (a bad key, an
unknown model) fails at once, and the report names the API's own error. A
response that cannot be parsed as a findings array is an **ERROR**, never "0
findings".

**Two honest limits.** Identity is anchored to the code (class + file + the
referenced line) rather than the model's wording, so a reworded finding keeps its
fingerprint — measured at 3 of 4 stable across independent runs, not all 4, so
expect some baseline churn on this pass. And it costs money and minutes per run;
it suits a nightly or pre-release job better than every push.

### When to run it — locally, before you release

**Recommended: run the review by hand before tagging a release**, not on a timer.
The default run already includes it (and the PDF):

```bash
./vibecheck.sh --open
```

That gives you the four pattern passes, the reasoning pass, a `report.pdf`, and a
formatted report open in your browser — a deliberate pre-release read rather than a
nightly digest nobody opens. (In provider-less CI, add `--no-review --no-pdf`.)

Locally you need **no credential of your own to manage**: if you already have the
`claude` CLI authenticated, `--review` uses it. Nothing to store, nothing to leak,
no runner minutes, and no surprise bill.

This suits the pass's character. It costs money and minutes, and its output is
probabilistic — findings you want to *read and think about*, not skim in a digest.
Ten minutes before a release beats a nightly you've learned to ignore.

**The nightly workflow is optional**, for teams who want the cadence and an audit
trail:

| Workflow | When | What | Gates? |
|---|---|---|---|
| [`ci/github-actions.yml`](ci/github-actions.yml) | every PR + push | four pattern passes | **yes** |
| [`ci/github-actions-review.yml`](ci/github-actions-review.yml) | nightly *(opt-in)* | the reasoning pass | no — report-only |

It needs an `ANTHROPIC_API_KEY` secret, because a CI runner has no credentials of
its own and nobody at the keyboard to log in. Add the secret **before** enabling
the schedule: VibeCheck fails closed, so `--review` without a provider exits 3, and
turning on the cron first gives you a red build that means "not configured" rather
than "found something". A scheduled job that cries wolf gets muted.

If you'd rather not store a key at all, the alternatives are a self-hosted model
via `--review-cmd`, or just staying with the local pre-release run above.

## AI / LLM & prompt-injection coverage

The SAST pass ships static rule packs under [`rules/`](rules/) for the sinks that
matter in LLM-backed apps and **MCP servers**, mapping to `AGENTS.md` §AI/LLM and
`hardening/CHECKLIST.md` §7 — [`vibecheck-ai.yml`](rules/vibecheck-ai.yml) and
[`vibecheck-ai-extra.yml`](rules/vibecheck-ai-extra.yml):

- **Untrusted input in a system prompt** — request data concatenated into the `system` channel (prompt injection). User-role content is normal and is *not* flagged.
- **LLM output executed** — a completion flowing into shell / SQL / `eval` without validation (an allowlist check clears it).
- **LLM output as raw HTML** — model text into `innerHTML`/`outerHTML` (XSS via the model).
- **Secret in an LLM prompt** — a `process.env` / `os.environ` value interpolated into a prompt (LLM02 sensitive-info disclosure — it lands in the provider's logs).
- **Unbounded LLM call** — an OpenAI-shaped chat/completions call with no `max_tokens` cap (LLM10 unbounded consumption — cost + latency DoS).

### OWASP-LLM Top-10 coverage (honest matrix)

Not every LLM risk is a regex. This is exactly what VibeCheck detects and how —
**scan** = deterministic SAST rule, **review** = the reasoning `--review` pass,
**checklist** = a manual item in `hardening/CHECKLIST.md` / `AI-GOVERNANCE.md`:

| OWASP-LLM (2025) | How VibeCheck covers it |
|------------------|-------------------------|
| **LLM01** Prompt Injection | **scan** + review + checklist |
| **LLM02** Sensitive Information Disclosure | **scan** (secret→prompt) + review + governance |
| **LLM03** Supply Chain | dependency + IaC passes; **checklist** (model/data provenance) |
| **LLM04** Data & Model Poisoning | **checklist / governance** — not statically detectable |
| **LLM05** Improper Output Handling | **scan** (exec / SQL / raw-HTML) + review |
| **LLM06** Excessive Agency | **review** + checklist (human gate on high-impact tools) |
| **LLM07** System Prompt Leakage | **review** + checklist (don't return the system prompt) |
| **LLM08** Vector/Embedding Weaknesses | **checklist / governance** — not statically detectable |
| **LLM09** Misinformation | **checklist / governance** — not statically detectable |
| **LLM10** Unbounded Consumption | **scan** (no token cap) + checklist (rate/spend limits) |

We intentionally do **not** ship a regex for LLM03/04/06/07/08/09 — a rule for a
class a regex cannot catch produces false confidence, which on a security gate is
worse than an honest gap. Those are carried by the review pass and the checklists.

### SSRF & resource-exhaustion

Two non-LLM packs the pentest feedback asked for:

- **SSRF** ([`vibecheck-ssrf.yml`](rules/vibecheck-ssrf.yml)) — a request-controlled URL fetched server-side with no host allowlist (CWE-918), the path to the cloud metadata endpoint and internal services. Taint-tracked in JS/TS, Python, Go, Ruby, PHP; an allowlist check clears it (modeled for JS/TS + Python). Java/C# SSRF is left to the review pass + checklist.
- **Resource-exhaustion** ([`vibecheck-resource.yml`](rules/vibecheck-resource.yml)) — the application-layer slice of "DDoS" that is actually visible in source: user-controlled regex (ReDoS), archive `extractall` with no size/path guard (zip bomb + zip-slip), and outbound calls with no timeout. Network/volumetric DoS is an edge concern (rate limits, WAF, autoscaling) and VibeCheck does not claim to scan for it.

Every rule in `rules/` is verified by a vulnerable + safe fixture under
`tests/ai-fixtures/`, checked with `semgrep --test` (35 rules) and gated in CI —
the rules do not ship unless they provably fire on the bad case and stay quiet on
the good one.

The AI/SSRF rules are deterministic and provider-anchored (Anthropic / OpenAI shapes) and cover **JavaScript/TypeScript, Python, Go, Ruby, Java, C#, and PHP** (SSRF: JS/TS, Python, Go, Ruby, PHP). They complement the reasoning `--review` pass, which now carries dedicated `prompt-injection`, `insecure-llm-output`, and `mcp-tool-safety` finding classes for the logic-level cases a regex can't reach — injection via tool arguments or retrieved content, MCP tool-description poisoning, and unvalidated tool args reaching a shell. An MCP server scans like any codebase at those two layers. On top of them, `--mcp` adds a **dynamic, read-only protocol probe**:

```bash
./vibecheck.sh --mcp "node build/server.js"      # stdio: spawn and probe
./vibecheck.sh --mcp https://mcp.example.com/    # streamable-HTTP transport
```

It completes the JSON-RPC handshake, enumerates the server's **tools, resources, and prompts**, and flags **tool-description poisoning** (instruction text that could steer a calling model), **unconstrained dangerous arguments** (a `command`/`url`/`path` arg with no allowed-values constraint that could reach a shell/SQL/SSRF sink), **secrets in metadata**, and — over HTTP — a server that accepts an **unauthenticated** session. It **never invokes a tool** — listing metadata only — so it stays non-destructive. A missing/unreachable server is an ERROR (exit 3), not a clean pass.

## Compliance mapping: CWE, OWASP Top 10, ASVS

Every finding carries a `taxonomy` object in `findings.json`, so it can be filed
against the control an auditor asks about:

```json
"taxonomy": { "cwe": ["CWE-89"], "owasp": ["A03:2021 - Injection", "A05:2025 - Injection"], "asvs": [] }
```

- **CWE** comes from the scanner where it says (semgrep rule metadata, ZAP, nuclei,
  testssl.sh), else from VibeCheck's own mapping for its own checks: dependency and
  image CVEs → CWE-1395, end-of-life OS → CWE-1104, secrets → CWE-798, missing
  headers, cookie flags and TLS problems → their specific CWE.
- **OWASP Top 10**: semgrep's own labels (any year), plus the **2021** category
  derived from the CWE through the official 2021 category lists. One label per
  category; spellings are normalised.
- **ASVS 4.0.3**: only where a check corresponds to one requirement (cookie flags
  V3.4.1-3, TLS V9.1.x, security headers V14.4.x, CORS V14.5.3, components V14.2.1,
  secrets V2.10.4).
- Anything VibeCheck cannot map stays empty. Nothing is guessed, and licence
  findings (legal, not security) carry none.

`report.md` adds a CWE column and a findings-per-OWASP-category table (unmapped
ones are counted); SARIF rules carry `external/cwe/cwe-N` tags, which GitHub Code
Scanning shows and filters by. This is evidence for an audit, not a compliance
certification.

## What this scan cannot see

Every report ends with the classes of flaw pattern scanning cannot detect at all —
business-logic authorisation, multi-tenant isolation, object lifecycle bugs
spanning files, races, session-invalidation semantics, and the absence of a
required control. The same list is in `findings.json` under `coverage`, so a
consumer can tell "clean" from "never looked" without parsing prose.

`report.md` also records **which tool at which version with which ruleset**
produced the result. A registry ruleset change silently alters what clean means;
this makes that auditable.

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

## In your AI coding assistant

CI catches problems after a push; the assistant writing the code can catch them
before it says "done". Two files make it do that. Both are plain text, free, and
cover the default scan only: the paid review pass runs only when you ask.

- **[`AGENTS.md`](AGENTS.md)**: copy it to your project root. Besides the secure
  coding rules, its *When you finish a feature* section tells the assistant to
  run VibeCheck, fix what it finds, and treat exit 3 as not clean.
- **[`.agents/skills/vibecheck/`](.agents/skills/vibecheck/SKILL.md)**: the full
  procedure as an [Agent Skill](https://agentskills.io): locate the script,
  scan, read `findings.json`, fix in priority order (verified secrets and CISA KEV
  first), re-scan, and report. Copy the `vibecheck` folder into your assistant's
  skills directory:

  | Assistant | Project | User (all projects) |
  |---|---|---|
  | Codex | `.agents/skills/` | `~/.agents/skills/` |
  | Any other assistant that reads Agent Skills | see your tool's docs | see your tool's docs |

Both forbid the assistant from making a scan pass by hiding findings (editing the
baseline or ignore files, inline suppressions, skipping a pass) without your
explicit approval. The decision to accept a finding stays with you.

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

## Testing VibeCheck itself

```bash
semgrep --test --config rules/ tests/ai-fixtures   # every rule fires on bad, quiet on good
shellcheck -S warning vibecheck.sh
bats tests/vibecheck.bats                           # the fail-closed contract
```

`tests/vibecheck.bats` pins the behaviour a security gate lives or dies by — every
path where a pass cannot complete must exit 3, not 0. It needs only bash, jq and
[bats](https://github.com/bats-core/bats-core): no scanners, network, or API key
(the model provider and the HTTP API are faked). All three run in CI.

### Detection benchmark: does it still find things?

The tests prove VibeCheck fails closed; they cannot prove it **detects**. A scanner
upgrade, a registry ruleset change or a parsing bug can silently stop a whole class
of finding with every test green. The
[benchmark workflow](.github/workflows/vibecheck-benchmark.yml) scans
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (pinned release, source
and running container, `--dast`) and asserts each of its documented flaws is still
found: SQL injection in login and search, SSRF, code injection, reflected XSS, an
open redirect, a hard-coded JWT secret and RSA key, the deliberately outdated
`jsonwebtoken` / `express-jwt` / `sanitize-html`, a workflow template injection, and
ZAP / nuclei / header findings on the live app. It runs weekly and on any change to
the scanner or its rules.

```bash
tests/benchmark/check.sh vibecheck-report/findings.json                # all checks
tests/benchmark/check.sh vibecheck-report/findings.json "" sast,secrets   # source-only run
```

The expectations live in [`tests/benchmark/expected.json`](tests/benchmark/expected.json),
one `jq` selector per known vulnerability. A pass that did not complete fails the
benchmark too: its checks would mean nothing.

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
