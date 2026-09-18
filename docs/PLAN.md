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

1. **CI schema validator** so a malformed defect file fails the build ← next
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
