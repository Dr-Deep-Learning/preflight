# Preflight

[![ci](https://github.com/Dr-Deep-Learning/preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/Dr-Deep-Learning/preflight/actions/workflows/ci.yml)

**Pre-launch security review for applications built with AI coding tools.**

Point it at a project directory and it tells you, in language you can act on
without an engineer, which of a small set of high-frequency defects your app is
about to ship with — and exactly how to fix each one for your stack.

```console
$ preflight scan ./my-app

  Not safe to launch
  2 confirmed issues that can expose your users' data.

  stack: vite-react / supabase   rules run: 4   findings: 6

  ! [F2] Environment file committed to git
      .env:6
      .env:7
      .env:10
  ! [F2] Supabase service-role key is hardcoded in your source
      src/lib/supabaseClient.ts:7
  ! [F1] 3 tables may be readable by anyone  (unverified)
      supabase/migrations/0001_init.sql:10
      supabase/migrations/0001_init.sql:3
      supabase/migrations/0001_init.sql:18
  - [S2] OpenAI-style API key is in code that ships to the browser
      src/components/Chat.tsx:3
  - [S2] A secret is named with a public environment prefix
      .env:10
  - [S1] 1 payment webhook handler may accept forged requests  (unverified)
      api/webhook.js:7
```

---

## Why

A documented, narrow failure pattern: 88% of audited AI-built applications ship
with database row-level security switched entirely off, Lovable apps shipped an
anon key that granted unrestricted table reads (CVE-2025-48757, CVSS 9.3), and a
Supabase misconfiguration on one AI-built social network exposed ~1.5M auth
tokens within days of launch. The same handful of defects recurs across tens of
thousands of applications, because the tools that removed the friction of writing
code also removed the people who used to catch these.

Preflight is not a general-purpose scanner and is not trying to become one. It is
an opinionated checklist for one population, one class of failure, and one moment
— the week before launch.

## The architectural commitment

**The rule engine detects. The language model only explains. There is no code
path from the explanation layer back into detection.**

This is the design decision the whole project is organised around, and it is
enforced structurally rather than by prompt. `preflight.engine` cannot import
`preflight.explain`; explanation runs after a `Finding` already exists, receives
that finding and the stack fingerprint, and returns prose. It is never given the
source, never asked whether a finding is real, and cannot add, suppress, or
re-rank one. A test asserts this holds even when the explainer is actively
adversarial, and a second one reads the import graph out of the source with `ast`
and fails the build if any module under `explain/` ever imports the engine — the
`Explainer` protocol lives in `preflight.models` precisely so it never needs to.

The reason is commercial, not aesthetic. A hallucinated vulnerability in a report
sold to someone who cannot evaluate it destroys trust permanently and there is no
recovering the customer. Every finding must be reproducible by the person reading
it.

Two consequences fall out of the same commitment:

- **Findings are confirmed or unverified, and the difference is visible.** A
  `.env` on disk proves nothing; a `.env` that `git ls-files` reports as tracked
  is confirmed. Missing RLS in a migration is *intent*, not state — someone may
  have enabled it by clicking in the dashboard — so it is reported as unverified
  with the one-line query that settles it. Only confirmed fatal findings are
  allowed to say "not safe to launch".
- **The report says what it did not check.** Every rule declares its own blind
  spots and they are printed. A clean report that implies comprehensiveness is
  the one failure mode that could end this project.

## What it checks today

Four rules, versioned as ruleset `2026.09.2`. `preflight rules` prints the
current set; `GET /rules` serves it as JSON.

| ID | Tier | Check | Detects |
|----|------|-------|---------|
| **F1** | Fatal | Database access control | Tables created in SQL migrations with no `ENABLE ROW LEVEL SECURITY`, including the case where a policy exists but RLS was never enabled, so the policy is inert. Migrations are grouped per application, so a repository holding several apps is analysed as several databases rather than one |
| **F2** | Fatal | Privileged key exposure | Service-role JWTs, PEM private keys, Postgres URLs with passwords, AWS keys and Stripe secret keys written into source; environment files tracked by git |
| **F3** | Fatal | Application database in the repository | A SQLite database tracked by git. Table names and row counts are read; no column value ever is. A non-empty table named for people (`users`, `sessions`, `customers`) is the trigger — one row, not a threshold, because there is no count at which a stranger's record stops being a disclosure. Row count sets severity; a path under `fixtures/`, `seeds/` or `test/` lowers it by one level and never silences it |
| **S1** | Serious | Payment webhook verification | Stripe and Paddle webhook handlers that trust the request body without calling `constructEvent` / `unmarshal` or comparing an HMAC — so a forged `checkout.session.completed` would be believed |
| **S2** | Serious | Third-party key exposure | LLM, email, SMS and maps keys in code that ships to the browser, and secrets named with a `NEXT_PUBLIC_` / `VITE_` prefix that the bundler will inline |

Detection quality comes from three places rather than from bigger regexes:

- **Semantic confirmation.** Any JWT matches the Supabase pattern; only one whose
  payload decodes to `"role":"service_role"` is reported. The anon key, which is
  published on purpose, is shaped identically and is never a finding.
- **Stack gating.** Rules declare the stacks they apply to, and the engine skips
  the rest and records why. A Firebase project never sees the RLS rule, and the
  report says so rather than staying silent.
- **Narrow candidates for absence checks.** F1, F2 and S2 detect that something
  *is* present, which is easy to evidence. S1 detects that something is *missing*,
  which is two inferences deep — so it only considers a file that is server-side,
  references a payment SDK, and either lives at a webhook path or reads a signed
  header. Findings from it are always unverified, because verification may live in
  middleware this rule cannot see.

Severity says how urgent a finding is; **blast radius** says how much is exposed,
on a three-level scale — `contained`, `broad`, `total` — defined by how many user
records are reachable. Three named levels rather than a 0–100 score, because
nobody can say what distinguishes 92 from 90 and the ruleset only ever
distinguished three bands anyway.

## The defect catalog

`src/preflight/defects/` holds one YAML file per defect — fifteen today, covering
secrets, access control, injection, payments, cost and configuration. Each entry
carries a permanent ID, a CWE, worked bad and good examples, and a
`false_positive_notes` field describing the safe code that looks like the defect.

The catalog is the shared vocabulary. A rule declares which entries it implements
(`catalog_ids`), so a deterministic check and a future model-driven one that find
the same defect report the same ID and can be counted together. `preflight rules`
and `GET /rules` both print the mapping.

It is loaded and validated by `catalog.py`, and `tests/test_catalog.py` asserts
rather more than "the YAML parses":

- Stack tokens come from a closed vocabulary, so a typo fails the build instead
  of silently gating nothing. Tokens naming things the fingerprinter cannot yet
  detect — `express`, `serverless`, `vue` — are recorded as such, and an entry
  that mentions one gets **no** gate rather than a narrowed one. The tokens are a
  disjunction and `Applicability` conjoins its dimensions, so a narrowed gate
  would skip precisely the projects we failed to identify.
- The catalog's `critical`/`high`/`medium` and the engine's
  `FATAL`/`SERIOUS`/`HYGIENE` have exactly one mapping between them, and the
  three places where a catalog entry and its rule currently disagree are listed
  explicitly in the test. Each is a decision someone owes an answer to.
- Every glob is expanded and matched against the fixture corpus. The patterns
  that reach nothing are enumerated, so a corpus gap is visible and a broken
  pattern fails the build.

That last one exists because it caught a real bug: written as
`supabase/migrations/**/*.sql`, the catalog's globs matched **nothing**.
`PurePath.match` treats a mid-pattern `**` as a single `*`, and understands no
brace alternation at all. Matching now goes through `pathspec` with gitignore
semantics, which is what anyone writing these patterns already expects.

## Install and use

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```console
git clone https://github.com/Dr-Deep-Learning/preflight
cd preflight
uv sync
uv run preflight scan ./path/to/your/app
```

Useful flags:

```console
uv run preflight scan ./app --json report.json --html report.html
uv run preflight scan ./app --fail-on serious   # CI gate; exits non-zero
uv run preflight scan ./app --explainer anthropic   # needs ANTHROPIC_API_KEY
uv run preflight rules
```

The exit code is part of the interface: non-zero when anything at or above the
threshold was found, so the same binary works as a pre-commit hook and a CI step.

### As a service

```console
PREFLIGHT_ALLOWED_ROOTS=/srv/checkouts uv run uvicorn preflight.service.app:app
```

```
POST /scans                  {"path": "/srv/checkouts/my-app"}  -> 202 {scan_id}
GET  /scans/{id}                                                -> state + full result
GET  /scans/{id}/report.html                                    -> the rendered report
GET  /rules                                                     -> the published ruleset
```

`PREFLIGHT_ALLOWED_ROOTS` is not optional. With it unset the service refuses
every scan with a 503. Failing closed matters more than convenience here: the
failure mode of failing open is reading directories nobody agreed to hand over.

### As a container

```console
make docker-build
docker run --rm -p 8000:8000 \
  -e PREFLIGHT_ALLOWED_ROOTS=/scan \
  -v "$PWD/fixtures:/scan:ro" preflight:dev
```

## Layout

```
src/preflight/
  models.py        Domain types. One schema for the API, the report and the tests.
  ingest.py        Mode A (local directory) + the FileIndex/GitInfo seam.
  fingerprint.py   Framework, backend, auth, payments; and what counts as client code.
  engine.py        Rule protocol, registry, stack gating, ranking, verdict.
  catalog.py       Loads and validates the defect catalog; the shared vocabulary.
  defects/         One YAML file per defect. Ships inside the package.
  rules/           One module per check. Importing the package registers them.
  explain/         Strictly downstream of detection. Static by default, Claude optional.
  report/          JSON is canonical; HTML renders from it.
  service/         FastAPI. Owns transport and the ownership guardrail, nothing else.
fixtures/
  vulnerable-app/  Vite + React + Supabase + Stripe, four planted defects.
  clean-app/       Next.js + Supabase + Stripe, built correctly. Always comes back clean.
```

Adding a check is adding one module in `rules/`: declare `id`, `title`,
`severity`, an `Applicability` gate and your blind spots in `limits`, then
implement `check(ctx) -> Iterable[Finding]`. Nothing else in the system changes —
S1 was added exactly that way, as one module plus one line in `rules/__init__.py`.

## The fixture corpus

Two small real applications, not mocks. Every assertion in the suite runs against
files a scanner would actually meet.

`clean-app` is the more valuable of the two and is written to be hard to pass by
accident. It hardcodes a Supabase **anon** key in a client component, commits an
`.env.local` holding three `NEXT_PUBLIC_` variables of which two end in `_KEY`,
keeps its privileged Stripe call in an `app/api/` route handler, and answers its
webhook with a correctly verified `constructEvent`. A scanner that matches on
shape alone fires on all four. **If a rule fires on `clean-app`, the rule is
wrong.**

Every credential in `fixtures/` is synthetic: unsigned JWTs, a domain that does
not resolve, keys shaped like the real thing and valid with nobody. They are
committed deliberately — a `.env` git is not tracking cannot reproduce the defect
F2 is about — which is why `.gitignore` carries explicit negations for
`fixtures/**/.env`.

## Guardrails

These come from the spec and are not negotiable, because for a solo operator they
are the existential risks rather than the engineering ones.

- **Scan only what you own.** Ingestion is a local directory, and the service
  refuses paths outside configured roots. No URL probing of anything you do not
  control — not once, not for a demo.
- **Observation, never exploitation.** Findings are established from
  configuration state. The scanner detects that RLS is missing; it does not read
  the table.
- **No retention of source.** Nothing in `ScanResult` contains code. Evidence
  snippets are redacted at construction, so no credential can reach a report or a
  model prompt even by accident.
- **Never claim comprehensiveness.** Every report ends by stating that passing it
  does not mean the application is secure.

## Not built yet

Deliberately deferred. The design is settled; the code is not written.

| Deferred | Design |
|---|---|
| **F4** server-side authorization | Endpoints that check authentication but not *ownership*. Needs call-graph analysis of route handlers, not pattern matching; the parser work is the reason it is not in week one. |
| **F5** public admin surface | Route enumeration plus an unauthenticated request per candidate. Requires the URL-probe ingestion mode and therefore ownership verification first. |
| **S3–S5, Tier 3** | String-built SQL, dependency integrity, auth configuration, headers, CORS, rate limits. Each is a module in `rules/`; none needs an architectural change. |
| **Mode B** backend connect | A read-only Supabase credential scoped to schema and policy inspection. Turns F1 from unverified into confirmed, and is the highest-value item on this list. |
| **Mode C** URL probe | Client-bundle analysis and header inspection on a deployed app. Gated behind ownership verification by DNS TXT or a file served at a known path — no exceptions, including demos. |
| **Ownership verification** | Prerequisite for Modes B and C. Nothing that touches a remote host ships before it. |
| **`SECURITY-FINDINGS.md` PR** | Write the report into the repo as a pull request. Also a distribution channel. |
| **Hosted product** | Ownership verification, billing, report design, monitoring and drift detection stay in a separate private repo. Open core: the scanner is the credibility artifact and publishing the ruleset openly is the distribution plan. |

## Development

```console
make install     # uv sync
make check       # ruff + mypy --strict + pytest, exactly what CI runs
make demo        # scan the vulnerable fixture, write out/demo.{json,html}
make serve       # run the API against fixtures/
```

CI runs the suite on 3.11 and 3.12, builds the image, and then does the thing
that actually matters: asserts the scanner **fails** on `vulnerable-app` and
**passes** on `clean-app`. A green suite with a scanner that finds nothing is the
failure this catches.

Two things the suite does that are worth knowing about before you edit anything:

- **`--doctest-modules` is on**, and `src` is a testpath, so every `>>>` example
  in a docstring is collected as a test. Documentation that stops being true fails
  the build rather than quietly rotting.
- **`tests/test_architecture.py` reads the import graph.** It fails if `explain/`
  ever imports the engine, if the engine imports `explain/`, if a rule imports
  `explain/`, or if `models` grows a dependency on anything inside the package.
  The architecture is checked, not just described.

## Scope statement

Passing this scan does not mean your application is secure. It means the specific
defects in the published ruleset were not found in the code it could read. The
ruleset covers the failure modes that most often breach applications like yours.
It is not a penetration test, it does not evaluate business logic, and it is not a
substitute for a security review.

## License

Apache-2.0.
