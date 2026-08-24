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
| 🧠 SAST | Insecure code patterns (injection, authz, crypto, XSS…) **+ AI/LLM prompt-injection** | semgrep + [`rules/`](rules/) |
| 📦 Dependencies | Known CVEs in your lockfiles (all sources run, results merged) | trivy + osv-scanner + npm audit + grype |
| 🐳 IaC / Containers | Dockerfile / Terraform / K8s misconfig | trivy config |
| 🌐 Dynamic *(opt-in)* | HTTP security headers, cookie flags, CORS, TLS version + cert expiry | curl, openssl |
| 🧭 Review *(opt-in)* | Access control, tenant isolation, lifecycle, races, missing controls | an LLM (`--review`) |

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
| `--review` | — | Adversarial reasoning pass (**report-only** by default) |
| `--fail-on-review` | — | Let surviving review findings affect the exit code |
| `--review-model` | `claude-opus-5` | Model for the review pass |
| `--review-effort` | `high` | `low\|medium\|high\|xhigh\|max` |
| `--review-budget` | `200000` | Max bytes of source sent for review |
| `--review-skeptics` | `2` | Independent refutation attempts per finding |
| `--review-cmd CMD` | — | Provider override: prompt on stdin, text on stdout |
| `--mcp TARGET` | — | Probe a running MCP server (read-only): URL or command to spawn |
| `--mcp-timeout N` | `20` | MCP handshake timeout (seconds) |
| `--mcp-header H` | — | One HTTP header for an authed MCP endpoint |
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

**Providers**, in precedence order: `--review-cmd` (anything — prompt on stdin,
text on stdout, so self-hosted models work), `ANTHROPIC_API_KEY` (the HTTP API),
or a local `claude` CLI. If `--review` is requested and none is available, that is
an **ERROR (exit 3)** — never a quiet "reviewed, found nothing".

**Two honest limits.** Identity is anchored to the code (class + file + the
referenced line) rather than the model's wording, so a reworded finding keeps its
fingerprint — measured at 3 of 4 stable across independent runs, not all 4, so
expect some baseline churn on this pass. And it costs money and minutes per run;
it suits a nightly or pre-release job better than every push.

### When to run it — locally, before you release

**Recommended: run the review by hand before tagging a release**, not on a timer.

```bash
./vibecheck.sh --review --pdf --open
```

That gives you the four pattern passes, the reasoning pass, and a formatted report
open in your browser — a deliberate pre-release read rather than a nightly digest
nobody opens.

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

The SAST pass ships a static rule pack ([`rules/vibecheck-ai.yml`](rules/vibecheck-ai.yml)) for the sinks that matter in LLM-backed apps and **MCP servers**, mapping to `AGENTS.md` §AI/LLM and `hardening/CHECKLIST.md` §7:

- **Untrusted input in a system prompt** — request data concatenated into the `system` channel (prompt injection). User-role content is normal and is *not* flagged.
- **LLM output executed** — a completion flowing into shell / SQL / `eval` without validation (an allowlist check clears it).
- **LLM output as raw HTML** — model text into `innerHTML`/`outerHTML` (XSS via the model).

These are deterministic and provider-anchored (Anthropic / OpenAI shapes), verified against vulnerable *and* safe fixtures so they stay quiet on ordinary code. They complement the reasoning `--review` pass, which now carries dedicated `prompt-injection`, `insecure-llm-output`, and `mcp-tool-safety` finding classes for the logic-level cases a regex can't reach — injection via tool arguments or retrieved content, MCP tool-description poisoning, and unvalidated tool args reaching a shell. An MCP server scans like any codebase at those two layers. On top of them, `--mcp` adds a **dynamic, read-only protocol probe**:

```bash
./vibecheck.sh --mcp "node build/server.js"      # stdio: spawn and probe
./vibecheck.sh --mcp https://mcp.example.com/    # streamable-HTTP transport
```

It completes the JSON-RPC handshake, enumerates the server's **tools, resources, and prompts**, and flags **tool-description poisoning** (instruction text that could steer a calling model), **unconstrained dangerous arguments** (a `command`/`url`/`path` arg with no allowed-values constraint that could reach a shell/SQL/SSRF sink), **secrets in metadata**, and — over HTTP — a server that accepts an **unauthenticated** session. It **never invokes a tool** — listing metadata only — so it stays non-destructive. A missing/unreachable server is an ERROR (exit 3), not a clean pass.

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
