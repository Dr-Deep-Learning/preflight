# Preflight — project plan

**Status:** working plan, not a specification. Supersedes nothing in the README;
the README describes what exists, this describes what is intended.
**Last updated:** 2026-09-18

---

## Goals

1. Learn industry-grade engineering by building a public repo quickly and gain
   traction to show potential employers. Background is research-grade ML coding.
2. Explore an extended version as a possible product or service.

Preflight is a pre-launch safety check for apps built by non-coders using AI
tools (Lovable, Bolt, v0, Cursor, and similar).

## Current state

- Rule-based Preflight works locally, is public on GitHub, with About and topics
  set.
- New: `defects/` folder in the repo root holding the defect catalog (15 YAML
  files + `README.md`). Not yet wired into the engine.

## Architecture decisions

- **Hybrid detection.** Keep deterministic rules (fast, free, reliable). Add an
  LLM layer driven by the defect catalog for issues rules cannot catch.
- **Catalog is one YAML file per defect**, filename = lowercase ID (for example
  `auth-001.yaml`). IDs are permanent; never renumber or reuse. Retire with
  `status: deprecated`.
- **Fields:** `id`, `title`, `category`, `severity`, `detector` (`rule` | `llm` |
  `both`), `status` (`active` | `experimental` | `deprecated`), `applies_to`
  (stacks, globs), `cwe`, `description`, `why_ai_apps`, `bad_example`,
  `good_example`, `false_positive_notes`, `references`.
- **`detector: both`** means a cheap rule finds candidates and the LLM confirms,
  so LLM cost scales with suspicious code, not repo size.
- **LLM output must be structured:** file, line, defect ID, confidence,
  explanation.
- **`false_positive_notes`** feed the LLM prompt *and* define the hard negatives
  for evals.
- Existing rule checks should be mapped to catalog IDs so rules and LLM report in
  one vocabulary. The four rules that exist today map as:

  | Rule | Catalog ID |
  |---|---|
  | F1 — missing row-level security | AUTH-001 |
  | F2 — privileged key in source | SEC-001 |
  | F2 — environment file committed | SEC-003 |
  | S1 — unverified payment webhook | PAY-001 |
  | S2 — third-party key reaching the browser | SEC-002 |

  AUTH-003 (open Firebase rules) and CFG-001 (CORS) have no corresponding rule
  yet — they are catalog entries awaiting implementation, not overlaps.
- Loader should read only `*.yaml` in the catalog directory (skip `README.md`).
- **Packaging caveat:** if Preflight is pip-installed, a top-level `defects/`
  will not ship in the package. Move it inside the package (for example
  `src/preflight/defects/`) and load with `importlib.resources`. The same applies
  to the container: the `Dockerfile` copies only `src`, so a top-level `defects/`
  never enters the image and the container will break as soon as the loader needs
  it, while local runs keep working. Fine as-is only while it is run from a clone.

## Catalog (15 defects)

**Secrets**

- `SEC-001` hardcoded secret — rule
- `SEC-002` privileged key exposed to browser — both
- `SEC-003` `.env` committed — rule

**Access control**

- `AUTH-001` Supabase table without RLS — both
- `AUTH-002` always-true RLS policy — both
- `AUTH-003` open Firebase rules — rule
- `AUTH-004` frontend-only authorization — llm, experimental. Exclude from
  headline metrics until evals prove it.
- `AUTH-005` API route without auth — llm
- `AUTH-006` IDOR — llm

**Injection**

- `INJ-001` SQL via string interpolation — both
- `INJ-002` unsanitized HTML / XSS — both

**Payments**

- `PAY-001` Stripe webhook without signature verification — both
- `PAY-002` client-supplied price — llm

**Cost**

- `COST-001` unprotected LLM proxy endpoint — llm

**Config**

- `CFG-001` CORS reflecting origin with credentials — rule

## Evaluation plan

The key differentiator. **Build the eval set before the LLM layer** so the
current rules get a baseline score and the LLM's added value is measurable.

### Tier 1 — curated cases

- `evals/cases/<defect>-positive-NN/` and `<defect>-negative-NN/`
- Labels in `evals/labels.jsonl`: `{case, defect_id, file, line, present}`
- Scored by `evals/run_eval.py`
- Start with roughly 5 defects x 4–6 cases.
- **Hard negatives are essential** — safe code that looks like the defect. For
  example Prisma's tagged `$queryRaw` (safe) versus `$queryRawUnsafe` (unsafe).

### Tier 2 — real repos

- Run against real AI-built open-source applications.
- Only **precision** is measurable there; each finding is triaged manually.
  Recall is not measurable, because ground truth is unknown.
- Best labeled source is **fix commits** — "enable RLS", "remove hardcoded key",
  "verify webhook signature". The commit before the fix is a positive, the commit
  after is a hard negative.
- Find AI-built apps via tool fingerprints (a `lovable-tagger` dependency, a
  `.bolt/` folder). Verify the fingerprints before relying on them.
- Pin commit SHAs. Store references (URL + SHA + path) rather than copying other
  people's code into this repo.

### Ethics

Disclose live secrets or open databases privately to their owners. Publish only
aggregate numbers, never repository names carrying unpatched findings.

### Metrics

- Per-defect precision and recall
- Overall false-positive rate
- For LLM checks: cost and p50 latency per scan, per model

Keep a results table in the README and update it as prompts and the catalog
improve.

## Roadmap

1. ~~**CI schema validator** so a malformed defect file fails the build~~ —
   **done**, as `catalog.py` plus `tests/test_catalog.py` rather than a separate
   script and workflow step, since CI already runs pytest. See "What step 1
   settled" below. ← **next is step 2**
2. First eval cases + scoring script; baseline the existing rules
3. Catalog-driven LLM layer with structured output; compare against the baseline
4. Real-repo tier (fix-commit mining)
5. MCP server wrapper so coding agents can call Preflight
6. Polish README and CI; publish a write-up with the metrics table; share it
7. Later: a focused agent that runs Preflight, triages findings, and proposes
   fixes
8. Meanwhile: a few upstream PRs to related projects, while applying for jobs

## Tooling note

Cowork for writing, research and general work. Consider Claude Code for the eval
harness and the MCP server — tight run-test-fix loops, and Claude Code is itself
an MCP client, which makes it useful for testing the server.

---

## What step 1 settled

Building the loader forced four decisions that the plan had left implicit. All
four are now enforced by tests rather than convention.

**The catalog moved into the package.** `src/preflight/defects/`, read through
`importlib.resources`. The pip case was already noted; the container case was
worse — the Dockerfile copies `src` and nothing else, so a top-level `defects/`
would have broken the image while every local run kept working. A test asserts
the directory sits inside the package, and the wheel was checked to confirm all
fifteen files ship.

**Stack tokens are a closed vocabulary with an honest partial mapping.** The
catalog uses ten tokens; the fingerprinter models framework, backend, auth and
payments. Three tokens — `express`, `serverless`, `vue` — name things it cannot
detect at all, and `react` is not one framework but three. Since the tokens are a
disjunction and `Applicability` conjoins its dimensions, an entry mentioning an
undetectable token now produces **no** gate rather than a narrowed one: narrowing
would skip the check on exactly the projects we failed to identify. A test also
forbids any entry from constraining more than one dimension, because that is
where "or" in the catalog would silently become "and" in the engine.

**Globs needed a different matcher.** Written as `**/*.{js,ts}` and
`supabase/migrations/**/*.sql`, the catalog's patterns matched *nothing*:
`PurePath.match` treats a mid-pattern `**` as a single `*` and understands no
brace alternation. `FileIndex.matching` now expands braces and matches with
gitignore semantics via `pathspec`. Every pattern is checked against the fixture
corpus, and the ones that reach nothing are listed — a shopping list for fixtures
rather than a silent failure.

**The catalog and the rules disagree about severity in three places.** Recorded
in `KNOWN_SEVERITY_DISAGREEMENTS`, not papered over:

| Entry | Catalog | Rule | The question |
|---|---|---|---|
| SEC-002 | fatal | serious | Is a browser-reachable third-party key Tier 1 or Tier 2? The spec says Tier 2. |
| SEC-003 | serious | fatal | Is a committed `.env` less severe than a hardcoded key? The rule treats them alike. |
| PAY-001 | fatal | serious | Spec section 5 puts webhook verification in Tier 2; the catalog calls it critical. |

Resolve each deliberately and delete its entry from the test.

## Open question this plan raises

The README's central architectural claim is that **the rule engine detects and
the language model only explains**, enforced structurally and asserted by
`tests/test_architecture.py`. A catalog with `detector: llm` and `detector: both`
reverses that: the model becomes a detector.

That may well be the right evolution — the eval harness is exactly what would
make it defensible — but it needs to be a deliberate decision with the story
updated to match, not a drift. One way to keep both:

- LLM-produced findings are always `Confidence.UNVERIFIED` and can never set a
  fatal verdict. Only deterministic rules confirm.
- `detector: both` is then precisely the upgrade path: the rule finds the
  candidate, the model explains why it is probably real, and a finding is only
  promoted to confirmed when a rule can prove it.
- The architectural claim becomes "the model may propose a finding, never confirm
  one", which is still a strong and testable property.

Decide this before step 3, because it determines what the eval harness in step 2
is measuring.

## What the first real-repo survey settled

Four targets, three of them fingerprint-confirmed Lovable apps, scanned at
pinned SHAs. Five findings. The useful results were all negative ones.

**The only confirmed finding on a real repository was a false positive.**
`NassimEH/WeListenMusic@cf0df1b9` commits a `.env` whose every value reads
`your-<name>-here`. F2 reported it FATAL / confirmed / TOTAL blast radius.
Root cause: `secretish_assignments` matched on the variable *name* and only
checked that the value was non-empty — it never called the placeholder test
that lives three modules away and that the pattern matcher has used all
along. Two code paths disagreed about the same question. Fixed in ruleset
`2026.09.3`, with the file's real contents as the regression fixture.

That path had **zero test coverage**. The one branch that fired first on
real-world input was the one branch the fixture corpus never reached. This
is the argument for the survey existing at all: a corpus you wrote yourself
exercises the code you were thinking about.

**A name-only hit is now UNVERIFIED, never CONFIRMED.** Whether a file is
tracked by git is a fact; whether it holds a live credential is a separate
question, and matching a variable *name* does not answer it. The two were
collapsed into one flag. They are now two.

**Rule coverage is the number that explains a clean report.** Nine of
sixteen rule-target pairs were applicable. Every Lovable target ran two of
four rules, because F1 and S1 gate on Supabase and Stripe. A clean verdict
on a target where half the ruleset was skipped says nothing about the app.
`survey.py` now prints this ratio, and the triage sheet carries it per row.

**Pin HEAD, not an interesting-looking old commit.**
`eryngordon/quiz-lead-magnet-maker@222fc22` (April 2025) came back clean and
applicable-2-of-4. It had no backend at all at that SHA; the repo grew a
Supabase integration later. The scan was honest and nearly vacuous.

### Two hypotheses about *who* ships insecure apps

Both were proposed from the survey and neither survives it:

1. *Older builder versions were less careful.* All three Lovable targets
   declare `lovable-tagger ^1.1.7`. The sheet now carries a Version column,
   so this is visible rather than argued. The initial `^0.0.1` reading was a
   misread.
2. *Authors with few public repositories make these mistakes.* Possibly
   true, unmeasurable here, and not actionable — the scanner cannot
   condition on an author's GitHub history. It is also confounded with
   everything else that distinguishes a throwaway repo from a real one.

The deeper problem with both is the sampling, not the variable. Targets were
hand-picked, and picked by looking until something was found. That procedure
**cannot** produce a base rate; it can only produce precision. So:

> Precision may be published from the triage sheet. A *rate* — "N% of
> AI-built apps ship with X" — may be published only from a sampling frame
> fixed before the first scan: enumerate repositories whose `package.json`
> depends on `lovable-tagger`, order them by a fixed key, take the first N,
> pin each at its default-branch HEAD, scan all N, report all N including
> the clean ones.

Until that exists, the honest headline is a precision number and a scope
statement, not a prevalence claim.

### Disclosure log

- `WeListenMusic` — placeholders only. No live credential. Nothing to
  disclose; the finding was ours, not theirs.
- `resume-maximizer-tool` — a 39-character `AIzaSy`-prefixed Google API key
  hardcoded in `src/utils/geminiAI.ts`, public since March 2025. Correct
  shape for a live key. **Not tested, and must not be.** Private disclosure
  to the owner; the repository name does not appear in any published
  aggregate.

### Gap this survey opened — now closed as F3

`WeListenMusic` commits `prisma/dev.db`, a SQLite database, and runs
better-auth + Prisma + Postgres. Two gaps at once: no rule covers a
committed database file, and the catalog's stack vocabulary has no entry for
this backend, so F1's whole question — who can read these rows — was never
asked. A committed-database rule is cheap, stack-independent, and would have
been the one true finding in that repo.

**Built, as F3 / SEC-004, in ruleset `2026.09.4`.** Three decisions are worth
recording because each of them was a choice not to do the easier thing:

* *The contents are never read.* Table names and `COUNT(*)`, no column values.
  That is the project's scope statement applied to a case where breaking it
  would have been useful: the signal that separates seeded demo rows from real
  ones (do the addresses all end in `@example.com`?) lives in the values. The
  rule therefore cannot tell them apart, and says so in the finding instead of
  guessing.
* *One row is the trigger, not a threshold.* No count exists at which a
  stranger's record stops being a disclosure, or at which seed data becomes
  real, so any number would have been chosen to feel reasonable and defend
  nothing. The count sets severity and blast radius; it does not open the gate.
* *Path lowers the finding, never raises it and never silences it.* `test.db`
  full of real rows is a mistake people make.

Ingestion changed to support it: the file index was text-only (suffix
allow-list, 1 MB cap), so a database was invisible to every rule. `FileIndex`
now carries a separate `data_paths` list with its own size limit — separate
because decoding a database as UTF-8 produces byte soup that would trip the
pattern-matching rules. `matching()` spans both, since it asks about paths.

The corpus fixture demonstrates the path rule against itself:
`fixtures/vulnerable-app/data/app.db` is FATAL when the app is scanned on its
own and SERIOUS when this repository is scanned, because the second path runs
through `fixtures/`. Both are correct.
