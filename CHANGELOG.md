# Changelog

All notable changes to **VibeCheck** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **VibeCheck inside the coding assistant.** `AGENTS.md`'s *When you finish a
  feature* section now tells the assistant to run VibeCheck before saying it is
  done, fix what it finds, re-scan, and treat exit 3 as not clean.
- **`vibecheck` Agent Skill** (`.agents/skills/vibecheck/SKILL.md`): the full
  procedure, covering locating the script, scanning (review pass only on
  request, since it is paid), reading `findings.json`, fixing in priority order
  (verified secrets to rotate, CISA KEV, critical, high), re-scanning and
  reporting with the coverage caveat. Works in any assistant that reads Agent
  Skills; README lists where to install it.
- Both forbid making a scan pass by hiding findings (baseline or ignore-file
  edits, inline suppressions, skipped passes) without the user's approval.
- Tests: the skill's frontmatter is checked, and every flag the skill or
  `AGENTS.md` tells an assistant to use must exist in `--help` (58 tests).

## [0.10.0] — 2026-11-04

Adds the **CISA Known Exploited Vulnerabilities** check, and fixes a fail-open in the
review pass. (Supersedes the unreleased 0.9.1; everything below ships together.)

### Added

- **CISA KEV check** (step 3b, on by default). Dependency CVEs — including the CVE
  aliases of GHSA ids, from OSV's alias table and grype's related-vulnerability data —
  are matched against CISA's catalog, fetched fresh from cisa.gov. A match is raised to
  **critical** whatever its CVSS and labelled with CISA's due date and ransomware use;
  `findings.json` keeps `severity_original` and a `kev` object. Verified end to end:
  `jquery@3.4.1` (CVE-2020-11023) is rated medium by all four scanners and passed the
  default gate; with KEV it fails it.
- **KEV-aware baseline.** An entry accepted before its CVE was KEV-listed no longer
  suppresses it; `--write-baseline` records `"kev": true` for a deliberate acceptance.
- `--kev` (unreachable feed becomes an ERROR, exit 3), `--no-kev`, `--kev-file PATH`
  (air-gapped CI; warns when the copy is older than 14 days). Default-on with the feed
  unreachable warns and records *KEV NOT checked* rather than reddening the build.
- 9 KEV behaviour tests (fake scanners and feed; no network).

### Fixed

Seven of these were found by VibeCheck's own review pass, run against this repository
before release: two through the new `gemini-api` provider, five through `codex`. Each
has a test that fails on the unfixed script.

- **`--diff` review could send a host file to the model (data exposure).** Changed-file
  paths come from git, not the regular-file search, so a pull request could commit a
  symlink to, say, `~/.aws/credentials` and have its contents put in the review
  prompt. The review now reads only regular files whose real directory is inside the
  target; symlinks and out-of-tree paths are skipped with a warning.
- **One dependency finding per CVE + package hid the other lockfiles.** The same CVE in
  an unchanged and a changed lockfile merged into one finding that kept the first
  file, so `--diff` (or a baseline entry for the other file) could drop the new
  occurrence. The lockfile is now part of the merge key: one finding per lockfile.
- **`--diff` against a ref with no merge base gated on nothing.** In a shallow checkout
  `base...HEAD` fails; the error was discarded and only uncommitted files were treated
  as changed, so every committed finding left the gate. It is now an **ERROR (exit 3)**
  telling you to fetch full history.
- **A trufflehog crash read as "0 secrets".** Its exit status was recorded and never
  checked; with no output the pass reported clean. Exit codes other than 0 (and 183,
  `--fail`) are now an **ERROR (exit 3)** naming the failed scan and its stderr.
- **An `npm audit` error was accepted as a completed scan.** npm reports registry and
  auth failures as valid JSON (`{"error": ...}`); any parseable JSON was accepted and
  yielded 0 CVEs. A `vulnerabilities` report is now required; otherwise the pass errors
  with npm's own summary. (This path also crashed on an unset variable when npm was
  the only dependency source; fixed.)

- **`--diff` never gated grype-only CVEs or MCP findings.** The PR gate keeps findings
  whose file is in the diff, but grype findings carried the placeholder path
  `dependencies` and MCP findings carry the server URL/command — neither can match, so
  both were silently moved out of scope (a KEV-listed CVE seen only by grype included).
  grype findings now carry the lockfile grype read; MCP findings, like dynamic ones,
  describe the running target and always stay in scope. *Baseline note:* a grype-only
  finding's identity changes with its path, so re-accept it once with `--write-baseline`.
- **`--diff` never prioritised the PR's own files in the review.** The review reads the
  changed-file list to put those files first in its budget, but the list was written
  only later, in the Diff scope step. It is now computed before the review; on a repo
  larger than `--review-budget`, unchanged files no longer crowd out the PR's changes.
- **`--help` executed an external program.** The help text is an unquoted heredoc and
  contained a tool name in backticks, which the shell ran as a command substitution
  every time help was printed (present since the review pass shipped). Escaped; a test
  now asserts `--help` runs nothing.
- **The review pass silently skipped large files.** A hidden 120 KB per-file cap dropped
  any bigger file from the review context without a word and still reported "0
  findings" — on this repository it skipped `vibecheck.sh` itself (129 KB) and reviewed
  only 17 test fixtures (7 KB). The cap is gone; files are taken in priority order until
  `--review-budget` is spent, and any file that does not fit is **listed in the console
  and the report, with the pass marked PARTIAL**. Default budget raised 200 KB -> 400 KB
  (~100k input tokens; roughly $0.40 per review run at current Opus pricing).
- **Refutation judged the wrong code in large files.** Each skeptic was shown the first
  400 lines of the flagged file, so a finding at line 1,400 was weighed against unrelated
  code and — skeptics default to REFUTED — dropped. Skeptics now see a numbered window
  around the claimed line (150 before, 250 after).
- **The adversarial review could report "0 findings" for a review that produced
  nothing usable (fail-open).** A model response containing square brackets that
  was not a valid JSON array — prose such as `the handler at [server.js line 1] looks
  fine`, or output truncated after an inner `]` — was turned into an empty array and
  recorded as a clean review. It is now an **ERROR (exit 3)**, like every other pass
  that cannot complete. Plain prose with no brackets already failed closed.
- **Review API errors are no longer opaque.** The HTTP status is checked; a 4xx such as
  a bad key or unknown model fails at once with the API's own error type and message
  in the report, instead of "review provider returned nothing".
- **Transient review API failures are retried** (network, 408, 429, 5xx incl. 529
  overloaded) with backoff that honours `Retry-After`, capped at 120 s per wait —
  3 attempts by default, `VIBECHECK_REVIEW_RETRIES` to change it. One blip no longer
  turns a run into exit 3.
- **Bun projects using the text lockfile (`bun.lock`, the default since Bun 1.2) no
  longer fail with "no scannable lockfile".** Verified that trivy and osv-scanner both
  resolve vulnerabilities from it.

### Changed

- **The review pass works with any AI CLI, not one vendor's model.** New
  `--review-provider` (values in `--help` / the README); `auto` (default) uses the
  first available: `--review-cmd`, the HTTP API key, then whichever coding CLI is on
  PATH — OpenAI **Codex** and Google **Gemini** are now first-class alongside the
  existing CLI provider, plus Google's stateless **Gemini API CLI** (`gemini-api`, the
  recommended Gemini route since the Gemini CLI became enterprise-only on 2026-06-18).
  The Antigravity CLI (`agy`) is deliberately not supported: it takes the prompt only as
  an argument (Linux caps one at 128 KB) and cannot have its tools disabled.
  `--review-model` is now passed to every provider (previously
  the CLI path ignored it while the console claimed otherwise); left unset, each CLI
  uses its own default model. Effort maps to each CLI's native setting (ignored, and
  said so, where unsupported). A pinned provider that is missing is an ERROR and never
  falls back.
- **AI CLIs run locked down.** They are agents and the code under review may carry a
  prompt injection, so each runs from an empty scratch directory with tools disabled or
  its strictest read-only mode (no tools / no MCP; read-only sandbox, ephemeral; plan
  approval mode). Previously the CLI provider ran with its default tool set in the
  caller's working directory. CLI failures (not signed in, bad model) fail closed and
  name the error. The Gemini CLI silently downgrades its read-only approval mode in an
  untrusted folder; VibeCheck trusts only its empty scratch dir for the session, and
  discards the review (exit 3) if a downgrade is still reported. An individual Google
  account rejected by the enterprise-only Gemini CLI gets a pointer to `gemini-api`.
- **CLI providers retry transient failures**, with the same policy as the HTTP API:
  5xx / 429 / 529, "high demand", overloaded, rate limits and timeouts are retried with
  backoff (`VIBECHECK_REVIEW_RETRIES`, default 3 attempts); auth and usage errors are
  not. Found in a real run: a `gemini-api` 503 on a busy model failed the whole review.
  Retry notices now reach the console for both paths (they were swallowed before).
- **Quota and billing errors are told apart from load.** A model with no quota on the
  key's tier (`limit: 0`), an exhausted daily quota, or a billing problem fails at once
  with a `QUOTA/BILLING` hint naming the model, instead of being retried. Per-minute
  rate limits are still retried, now after the delay the API asks for ("retry in 23s").
- **Default HTTP-API review model moves to the current Opus generation** (see `--review-model`
  in `--help` / the README options table) — ~20% cheaper per token. Effort is still sent
  explicitly (`high`), so the new model's lower built-in default (`medium`) does not
  apply. `--review-model` restores the previous model.
- Refusal fallbacks use the server-chosen form (`fallbacks: "default"`, beta
  `server-side-fallback-2026-07-01`) instead of a hard-coded fallback model.

### Added (tests)

- **`tests/vibecheck.bats`** — 17 behaviour tests for the fail-closed contract (56 with the KEV, `--help`, review-coverage, provider, retry, `--diff` and scanner-failure tests): coverage
  guard, review parse/empty/refusal/no-provider paths, refutation, `--fail-on-review`,
  and HTTP API error/retry handling (provider and API faked; no network or key).
- CI: a `script-tests` job runs `shellcheck -S warning` and the bats suite.

### CI / housekeeping

- `.github/workflows/vibecheck-review.yml` was still pinned to v4 (Node 20) action SHAs
  missed by #14; now `checkout` v7.0.1 / `upload-artifact` v7.0.2. The main workflow
  moves to `upload-artifact` v7.0.2 and `setup-python` v7.1.0.
- Baseline entry (with reason) for the mutable tags in the copy-paste template
  `ci/github-actions-review.yml`, which surfaced as two medium findings in the self-scan.
- `.gitignore` covers every `vibecheck-report*/` output directory (renamed `--out` dirs
  hold real vulnerability reports and must not be committed by accident) and `.DS_Store`.
- shellcheck-clean at warning level (quoting only; no behaviour change).

## [0.9.0] — 2026-09-24

Acts on pentest feedback: broadens the deterministic SAST layer beyond
prompt-injection into **SSRF**, **application-layer resource-exhaustion**, and
the **rest of the OWASP-LLM Top 10** that a regex can honestly reach — plus an
**AI governance** checklist. The rule count goes from 22 to **35**, all gated by
`semgrep --test` in CI.

### Added

- **SSRF rule pack** (`rules/vibecheck-ssrf.yml`, CWE-918 / OWASP A10). Taint-tracks a
  request-controlled URL/host into an outbound HTTP client with no host allowlist —
  the path to the cloud metadata endpoint (169.254.169.254), internal services, and
  localhost. Covers **JavaScript/TypeScript, Python, Go, Ruby, PHP**; an allowlist
  membership check clears the finding (modeled for JS/TS + Python). Java/C# SSRF is
  deliberately left to the review pass + checklist rather than matched imprecisely.
- **Resource-exhaustion rule pack** (`rules/vibecheck-resource.yml`) — the slice of
  "DDoS" that is actually visible in source: **user-controlled regex** (ReDoS, CWE-1333,
  JS/TS + Python), **archive `extractall` with no size/path guard** (zip bomb + zip-slip,
  CWE-409, Python), and **outbound calls with no timeout** (CWE-400, Python `requests`).
  Volumetric/network DoS is explicitly out of scope — that is an edge concern (rate
  limits, WAF, autoscaling), and the docs say so instead of over-claiming.
- **OWASP-LLM Top-10 completions** (`rules/vibecheck-ai-extra.yml`) — **LLM02** secret/
  env value interpolated into a prompt (sensitive-info disclosure to the provider) and
  **LLM10** an OpenAI-shaped chat/completions call with no `max_tokens` cap (unbounded
  consumption). JS/TS + Python.
- **`hardening/AI-GOVERNANCE.md`** — a governance checklist for AI features (data-flow
  inventory, DPA/BAA + training opt-out, model provenance & pinning, evals/red-teaming,
  human oversight of agent actions, observability/audit, and GDPR/EU-AI-Act scope). These
  are the questions a scanner cannot answer but a security review or regulator will ask.
- **Honest OWASP-LLM coverage matrix** in the README, marking each of LLM01–LLM10 as
  covered by **scan**, **review**, or **checklist/governance** — and stating plainly that
  LLM03/04/06/07/08/09 get no regex on purpose, because a rule for a class a regex cannot
  catch produces false confidence.

### Changed

- The adversarial `--review` pass gains a dedicated **`ssrf`** finding class and a prompt
  bullet for the SSRF cases a pattern can't reach (allowlist via an unseen helper,
  DNS-rebinding, open redirects, parser/fetcher URL disagreement, and the Java/C# fetch
  idioms the static pack does not model).
- `hardening/CHECKLIST.md`: §3 gains ReDoS and archive-extraction items and a strengthened
  SSRF item; §6 gains outbound-timeout and input-cap items; §7 gains no-secrets-in-prompts
  (LLM02), excessive-agency gating (LLM06), system-prompt-leakage (LLM07), and an explicit
  token cap (LLM10), and now links to `AI-GOVERNANCE.md`.

## [0.8.0] — 2026-09-15

The release reframes VibeCheck around a **deep pre-release read** rather than a
pattern-only gate, and closes the credibility gap in the rule packs.

### Changed

- **The adversarial review pass now runs by default.** A default `./vibecheck.sh`
  run performs the four pattern passes *and* the reasoning pass. When no model
  provider is configured the review **skips gracefully** — the rest of the scan
  still runs and a provider-less CI job is not reddened. An *explicit* `--review`
  with no provider remains a fail-closed **ERROR (exit 3)**, so an intended review
  can never be silently absent. The pass stays **report-only** unless
  `--fail-on-review` is set, so turning it on by default does not newly redden any
  build.
- **PDF output is now default-on.** A default run renders `report.pdf` alongside
  the Markdown/HTML/SARIF outputs, warning (not failing) if no renderer
  (Chrome / wkhtmltopdf / weasyprint) is present.

### Added

- **`tests/ai-fixtures/` — a real `semgrep --test` harness for every rule.** The
  rule-pack header long claimed each rule was proven by a vulnerable + safe
  fixture; that harness now exists. 22 rules across seven languages are verified
  with `semgrep --test --config rules/ tests/ai-fixtures` and **gated in CI** — a
  rule cannot ship unless it provably fires on the bad case and stays quiet on the
  good one.
- **`--no-review`** and **`--no-pdf`** to opt out of the new defaults.
- **`--exclude PATH`** (repeatable) to exclude paths from scanning. It is
  operator-trusted — unlike config/ignore/baseline it is honoured even under
  `--base`/`--diff`, so CI can exclude the intentionally-vulnerable rule fixtures
  from the self-scan without a base-ref round-trip.

### CI / templates

- The live self-scan workflow verifies the rule packs (`semgrep --test`) before
  scanning, and runs the self-scan with `--no-review --no-pdf --exclude tests`.
- The copy-paste per-PR templates (`ci/github-actions.yml`,
  `ci/gitlab-ci.snippet.yml`) pass `--no-review --no-pdf`: the per-PR gate is the
  four pattern passes, with the review pass belonging in the nightly /
  pre-release job where a provider is configured.

## [0.7.1] — 2026-08-27

Administrative re-release of 0.7.0 on a clean commit. **No functional change** —
the rules, fixtures, and behaviour are identical to 0.7.0. The 0.7.0 tag was
retired and is not published; use 0.7.1. See the 0.7.0 entry below for the
actual feature changes.

## [0.7.0] — 2026-08-27

### Added

- **The AI / prompt-injection rules now cover Go, Ruby, Java, C# and PHP**, not
  just JavaScript/TypeScript and Python. The two core rules — request data
  flowing into an LLM *system* prompt (`LLM01`), and LLM output flowing into a
  shell/SQL/`eval` sink (`LLM05`) — are defined for all seven language groups,
  each anchored to the real SDK and framework shapes (Anthropic/OpenAI SDKs,
  LangChain4j, Semantic Kernel, `openai-php`, `ruby-openai`) and that language's
  request sources, so they stay quiet on ordinary code. The `llm-output-executed`
  rules are taint-tracked.
- **The raw-HTML rule (LLM output rendered as markup, `LLM05`) gains Python,
  Ruby, C# and PHP.** It is defined only where a server-side "trust this string
  as HTML" sink is crisp and idiomatic — `HTMLResponse`/`render_template_string`/
  `mark_safe`/`Markup`, `raw`/`.html_safe`, `Html.Raw`/`HtmlString`/`Response.Write`,
  `echo`/`print`. Go and Java are deliberately omitted: they render HTML
  template-side (Go `html/template`, Thymeleaf `th:utext`), out of a `.go`/`.java`
  file's reach.
- **FastAPI / Starlette request sources** added to the Python system-prompt rule
  (`request.query_params`, `request.path_params`, `request.headers`,
  `request.cookies`), so FastAPI apps and Python MCP servers are covered, not
  just Flask/Django.

Every rule is verified against a vulnerable + safe fixture per language (23
intended detections fire, zero false positives on the safe cases, zero parse
errors). The pack now carries 19 AI rules across 7 language groups.

> Heads-up for existing users: new `ERROR`-severity rules can surface findings in
> code that previously scanned clean — expected for added coverage, not a
> regression. Triage or baseline as usual.

## [0.6.1] — 2026-08-24

### Added

- **Python coverage for the AI/prompt-injection rules.** The two core rules —
  request data into an LLM *system* prompt, and LLM output flowing into a
  shell/SQL/`eval` sink — now run on Python (Flask/FastAPI/Django request
  sources; Anthropic/OpenAI Python SDKs), not just JavaScript/TypeScript. The
  `llm-output-executed` rule is taint-tracked with an allowlist-membership
  sanitizer, mirroring the JS/TS behaviour. Verified against a Python vulnerable
  fixture (all three occurrences fire) and a safe fixture (zero false positives,
  including allowlist-gated `subprocess.run` and user input kept in the user
  message). The raw-HTML rule stays JS/TS-only — LLM-output-to-HTML is rare and
  false-positive-prone server-side in Python.
- **MCP coverage across the prevent and verify layers**, completing the three-layer
  model for MCP (detect shipped in 0.6.0 as the AI rules + the `--mcp` probe):
  - `AGENTS.md` gains an **MCP servers** rule block — validate/allowlist tool
    arguments before shell/SQL/URL sinks, authenticate the transport, keep
    instruction text and secrets out of tool descriptions, treat tool results as
    untrusted, scope tools least-privilege.
  - `hardening/CHECKLIST.md` gains **§8 MCP servers** with the matching manual
    checks. Because the `--review` pass ingests the checklist, the reasoning
    review now asks these MCP questions automatically (verified: the new items
    appear in the generated review prompt).

## [0.6.0] — 2026-08-24

Opens AI/LLM security coverage — the first pass at testing the code that talks to models, including MCP servers.

### Added

- **AI / prompt-injection rule pack** ([`rules/vibecheck-ai.yml`](rules/vibecheck-ai.yml)) for the SAST pass, three deterministic rules mapping to `AGENTS.md` §AI/LLM and `hardening/CHECKLIST.md` §7:
  - **`untrusted-input-in-system-prompt`** — request-controlled data interpolated into an LLM *system* prompt (prompt injection). User-role content is deliberately not matched — that's the normal place for user input.
  - **`llm-output-executed`** — a completion flowing (taint-tracked) into a shell / SQL / `eval` sink without validation; an allowlist/membership check on the value clears it.
  - **`llm-output-raw-html`** — model output into `innerHTML`/`outerHTML` (XSS via the model), sanitizer-aware (DOMPurify).
  - Provider-anchored (Anthropic / OpenAI shapes), and verified against a vulnerable fixture (all three fire) *and* a safe fixture (zero false positives, including the allowlist-gated exec) so the pack stays quiet on ordinary code.
- **Dynamic MCP server probe (`--mcp`)** — connects to a running MCP server over
  stdio (spawn) or streamable-HTTP, completes the JSON-RPC handshake, and
  enumerates its tools / resources / prompts. It flags **tool-description
  poisoning**, **unconstrained dangerous arguments** (`command`/`url`/`path`-type
  string args with no allowed-values constraint), **secrets in metadata**, and —
  over HTTP — acceptance of an **unauthenticated** session. It **never invokes a
  tool** (metadata only), so it is non-destructive; an unreachable/uninitialisable
  server is an ERROR (exit 3), not a clean pass. Verified against poisoned and
  clean mock servers on both transports, authed vs unauthenticated, and the
  fail-closed path.
- **AI/MCP awareness in the reasoning `--review` pass** — three new finding
  classes (`prompt-injection`, `insecure-llm-output`, `mcp-tool-safety`) and an
  explicit, guarded AI/MCP lens in the review prompt: prompt injection via tool
  arguments / tool results / retrieved content escaping into the model's
  instruction context, LLM-output-as-action, MCP tool-description poisoning
  (confused deputy), unvalidated tool args reaching shell/SQL/SSRF, and missing
  auth on the MCP transport. The lens is skipped on non-AI/non-MCP code so it
  invents nothing there. Verified: on a minimal MCP server the pass emitted a
  critical `mcp-tool-safety` finding for a tool argument flowing unvalidated into
  a shell — a bug the static passes cannot see.
- The SAST pass now loads **every pack in `rules/`** (not just `vibecheck-extra.yml`), so future packs are picked up without wiring changes. The tooling manifest reports the pack count.

### Notes

- These static rules complement the reasoning `--review` pass, which catches logic-level prompt injection a pattern can't. An **MCP server** scans like any codebase, and the `--review` pass now reasons about MCP tool-safety and prompt injection specifically. The `--mcp` probe adds the dynamic layer, connecting to a running server to enumerate and vet its tools/resources/prompts (read-only). Actively *calling* tools to test runtime behaviour is intentionally out of scope — it would be destructive.

## [0.5.2] — 2026-08-18

### Fixed

- **The HTML report was missing three sections that `report.md` had:** the
  adversarial review findings (0.5.0), the tooling manifest and the explicit
  "not examined" list (0.4.0). This mattered more than a formatting gap — the
  recommended workflow is `--review --pdf --open`, so the HTML report is the
  artifact a human actually reads, and review findings were invisible in exactly
  the place they were meant to land. Found by diffing the section lists of the two
  reports rather than assuming they matched.
- When `--review` is **not** run, the HTML report now states that those classes
  went unexamined, instead of leaving a reader to infer clean from silence.

### Changed

- The README now recommends running the reasoning pass **locally before a
  release** (`./vibecheck.sh --review --pdf --open`) rather than on a nightly
  timer. It needs no stored credential if you have the `claude` CLI, produces a
  report you sit down and read, and suits a pass whose output is probabilistic and
  whose runtime is measured in minutes. The nightly workflow is documented as the
  optional alternative for teams wanting cadence and an audit trail.

## [0.5.1] — 2026-08-18

### Fixed

- **`--install` did not install osv-scanner**, despite the v0.4.0 release notes
  saying it did. The claim is now true. This is the documented-but-unimplemented
  class this project keeps having to fix — caught by re-reading a published note
  against the code.

### Added

- **A nightly review workflow** — `.github/workflows/vibecheck-review.yml` for
  this repo and [`ci/github-actions-review.yml`](ci/github-actions-review.yml) as
  a template. The reasoning pass runs on its own cadence: pattern passes are fast,
  deterministic and free so they gate every pull request, while the review costs
  money and minutes and produces probabilistic output, so it runs nightly and
  report-only.
  - The live workflow ships with its `schedule:` **commented out** on purpose.
    `--review` fails closed without a provider, so enabling the cron before the
    `ANTHROPIC_API_KEY` secret exists would produce a nightly red build meaning
    "not configured" rather than "found something".
  - A dedicated pre-flight step reports a missing secret as a configuration
    error, instead of letting the run reach pass 6 and report ERROR for what is
    not a problem with the code under review.
  - Findings are written to the run summary and uploaded as an artifact.

## [0.5.0] — 2026-08-18

The reasoning half. Everything before this release matched patterns; `--review`
reasons about the code, which is the only way to reach the classes a scanner
structurally cannot.

### Added

- **Adversarial review pass (`--review`)** — an LLM is given the code and asked
  who controls each input, where the trust boundary sits, and which required
  control is absent. Verified on a three-file fixture where the pattern passes
  report 0 findings and exit 0: the review pass reports the critical cross-tenant
  refund, a bug that exists only in the relationship between a session helper, a
  route, and an unscoped data layer.
  - **Report-only by default.** Model output is probabilistic; one false positive
    that reddens a build costs more trust than a missed finding. `--fail-on-review`
    opts in to gating. Review findings are excluded from the gate counts and from
    SARIF unless that flag is passed.
  - **Refutation.** Every candidate faces `--review-skeptics` independent
    challengers asked to argue *against* it, defaulting to refuted; a majority
    refuting drops it. Refuted candidates are counted, not reported.
  - **Code-anchored identity.** Fingerprints derive from class + file + the
    referenced line, not the model's prose, which is reworded every run.
    Measured at 3 of 4 stable across independent runs — better than title-based
    identity, but expect some churn on this pass.
  - **Prompt driven by `hardening/CHECKLIST.md`** so the automated and manual
    layers ask the same questions instead of drifting apart.
  - **Providers:** `--review-cmd` (any provider, prompt on stdin), the Anthropic
    HTTP API via `ANTHROPIC_API_KEY`, or a local `claude` CLI. Requesting
    `--review` with no provider available is an **ERROR (exit 3)**.
  - Context assembly prioritises files the diff touched, then likely
    trust-bearing entry points, up to `--review-budget` bytes — a logic bug spans
    files, so per-file review would miss what this pass exists to find.

### Fixed

- **`findx` dropped all but the last match expression.** `find`'s `-o` binds
  looser than the implicit `-a`, so `-type f -name a -o -name b -print` attached
  `-print` to the final term only. Every caller with multiple alternatives
  silently matched just one: `*.csproj` (.NET), `*.gradle` (Gradle), and `*.yaml`
  (Kubernetes manifests) were never detected. The expression is now parenthesised.
- **A review-only run reported "no pass examined anything."** The coverage guard
  added in 0.3.2 did not count `review` as a pass, so a run with the scanners
  skipped exited 3 despite having reviewed the code.

## [0.4.0] — 2026-08-18

Coverage release. 0.3.x could report "0 CVEs" while consulting only one advisory
database, and reported clean on code an adversarial review found three flaws in.

### Fixed

- **A delimiter bug silently corrupted findings.** Internal scanner output was
  parsed with `IFS=$'\t'`, and tab is an IFS *whitespace* character — so bash
  collapses consecutive and leading empty fields and shifts every later value
  left. A dependency finding with an empty severity score had its id replaced by
  a file path. All 11 parse loops now use ASCII unit separator (non-whitespace,
  so empty fields survive), with embedded newlines sanitised explicitly since
  `@tsv` no longer does it.
- **npm audit never ran when trivy was installed.** It was a fallback, not a
  source, so the npm/GitHub advisory database was never consulted on any machine
  with trivy present.
- **osv-scanner was advertised but never invoked.** It was dropped in the 0.2.0
  rewrite while the README kept listing it — the same documented-but-unimplemented
  class 0.2.0 set out to fix.

### Changed

- **Dependency sources are additive and merged.** trivy, osv-scanner, npm audit
  and grype all run; results are deduplicated on (vulnerability, package name).
  OSV's alias table canonicalises CVE↔GHSA so one vulnerability reported by two
  sources under two identifiers merges instead of double-counting. Package names
  are compared without the version, because npm audit omits it.
  - Findings record their corroborating `sources`, deliberately **outside** the
    fingerprint — installing another scanner must not invalidate a baseline.
  - Dependency findings now use a stable `deps` tool identity rather than the
    name of whichever scanner reported them first. **This changes dependency
    fingerprints once**; re-run `--write-baseline` to refresh accepted entries.

### Added

- **A supplementary semgrep rule pack** ([`rules/`](rules/)) for sinks the public
  registry does not reach: request data interpolated into a raw node `http`
  response (registry rules cover framework sinks like express `res.send`, not
  template literals in `res.end`), unbounded request-body accumulation, and
  unguarded `JSON.parse` of external input. Each rule was added because a real
  finding was missed, and each is verified against both a vulnerable and a
  correctly-written fixture so it stays quiet on the latter.
- **A tooling manifest** in `report.md` and `findings.json`: which tool, which
  version, which ruleset. A clean result is not auditable without it.
- **An explicit statement of what was not examined**, in every report and
  machine-readable under `coverage.not_detectable`.

## [0.3.2] — 2026-08-12

**Security fix. Configuration inside the scanned tree could disable the gate.**

### Fixed

- **In-tree configuration was trusted.** `vibecheck.yml`, `.vibecheckignore` and
  `.vibecheck-baseline.json` were read from the directory being scanned. In CI
  that directory *is* the pull request, so a change could suppress its own
  findings. All four of these turned a repo containing command injection and
  `eval()` on user input into a passing build:
  - `vibecheck.yml` with `fail_on: never`
  - `vibecheck.yml` disabling every scanner — reported as *skipped*, so
    fail-closed never fired and the run exited 0 with zero findings
  - `.vibecheckignore` naming the vulnerable file
  - a self-authored `.vibecheck-baseline.json` accepting its own findings

  Fixes, in layers:
  - **`--base REF`** (implied by `--diff`) reads all three files from a trusted
    git ref instead of the working tree, so a change cannot rewrite its own gate.
    `--trust-repo-config` restores the old behaviour where that is wanted.
  - A config file may no longer set **`fail_on: never`** unless the operator also
    passes `--fail-on never` on the command line. A total gate bypass now has to
    be typed by a human.
  - **If no pass examined anything**, the result is an ERROR rather than a clean
    exit 0. An empty scan is unknown, not clean — however it came to be empty.
  - The report no longer **misattributes** a config-driven skip to a `--skip-*`
    flag the operator never passed; it names the file that disabled the pass.

### Notes

- Found by comparing VibeCheck against an adversarial LLM review on the same
  codebase. The scanner and the review overlapped on nothing: the review found
  logic and lifecycle flaws no pattern engine can see, and this trust-boundary
  bug in VibeCheck itself is the same class — reading a config file is not a
  suspicious pattern, it only becomes a vulnerability once you ask who controls
  the file.

## [0.3.1] — 2026-08-11

### Fixed

- **A baseline entry could silently suppress new occurrences.** Identity is
  `tool|rule|file|title`, so when a scanner emits an identical message for every
  hit of a rule in a file — semgrep does this routinely — all hits collapse into
  one entry. Accepting it then also accepted any *future* hit of that rule in
  that file, with no signal. Entries now record how many findings they covered
  when accepted (`occurrences`), and VibeCheck warns, naming the new locations,
  when that count grows. Found while baselining this repository's own findings:
  five findings collapsed into a single entry.

### Added

- `.vibecheck-baseline.json` — this repository accepts the mutable action tags in
  `ci/github-actions.yml`, which is a copy-paste template that deliberately uses
  readable version tags. The reason is recorded in the entry; the live workflow
  is SHA-pinned and carries none of these findings.

## [0.3.0] — 2026-08-11

Adoption release. 0.2.0 made the tool trustworthy; this makes it usable on a
codebase that already exists — without weakening the fail-closed guarantee.

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

- **Diff-scoped gating** — `--diff REF` gates only on findings in files changed
  against a git ref, so a pull request fails for what it introduces rather than
  what it inherited. Findings outside the diff are still reported. Dynamic
  findings always count, since they describe the running application rather than
  a file in the diff. A missing ref or non-git target is an **ERROR (exit 3)**,
  not a silent scope-to-nothing. Pairs with the baseline: use `--diff` on pull
  requests and a full scan on your default branch.

### Fixed

- **The gitleaks path never scanned the working tree.** Only git history was
  scanned on a repository, so an uncommitted secret — exactly what a pre-commit
  check should catch — was invisible. Both history and the working tree are now
  scanned, and results deduplicated (`gitleaks git` reports repo-relative paths
  while `gitleaks dir` reports absolute ones, so the same secret was otherwise
  counted twice).
- **Migrated off the deprecated `gitleaks detect`/`--no-git`** to the `git` and
  `dir` subcommands, with a capability probe so older installs still work.
- `ci/github-actions.yml` referenced `aquasecurity/setup-trivy@v0.2.3`, which does
  not exist — copying the template produced an immediate CI failure. Now v0.3.1.
- `.gitignore` pattern `vibecheck.yml` was unanchored and matched at any depth,
  silently excluding `.github/workflows/vibecheck.yml` from commits.

### Added (CI)

- `.github/workflows/vibecheck.yml` — the repository is now gated by its own tool,
  with every action pinned to a commit SHA. Pull requests run in `--diff` mode;
  pushes to `main` run a full scan.

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

[Unreleased]: https://github.com/rabbai007/TestAndVibes/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/rabbai007/TestAndVibes/compare/v0.9.0...v0.10.0
[0.2.0]: https://github.com/rabbai007/TestAndVibes/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rabbai007/TestAndVibes/releases/tag/v0.1.0
