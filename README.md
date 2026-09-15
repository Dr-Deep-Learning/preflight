# Preflight

**Pre-launch security review for applications built with AI coding tools.**

Point it at a project directory and it tells you, in language you can act on
without an engineer, which of a small set of high-frequency defects your app is
about to ship with — and exactly how to fix each one for your stack.

```console
$ preflight scan ./my-app

  Not safe to launch
  2 confirmed issues that can expose your users' data.

  stack: vite-react / supabase   rules run: 3   findings: 5

  ! [F2] Supabase service-role key is hardcoded in your source
      src/lib/supabaseClient.ts:7
  ! [F2] Environment file committed to git
      .env:6
      .env:7
      .env:10
  ! [F1] 3 tables may be readable by anyone  (unverified)
      supabase/migrations/0001_init.sql:3
  - [S2] A secret is named with a public environment prefix
      .env:10
  - [S2] OpenAI-style API key is in code that ships to the browser
      src/components/Chat.tsx:3
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
adversarial.

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

Three rules, versioned as ruleset `2026.09.0`. `preflight rules` prints the
current set; `GET /rules` serves it as JSON.

| ID | Tier | Check | Detects |
|----|------|-------|---------|
| **F1** | Fatal | Database access control | Tables created in SQL migrations with no `ENABLE ROW LEVEL SECURITY`, including the case where a policy exists but RLS was never enabled, so the policy is inert |
| **F2** | Fatal | Privileged key exposure | Service-role JWTs, PEM private keys, Postgres URLs with passwords, AWS keys and Stripe secret keys written into source; environment files tracked by git |
| **S2** | Serious | Third-party key exposure | LLM, email, SMS and maps keys in code that ships to the browser, and secrets named with a `NEXT_PUBLIC_` / `VITE_` prefix that the bundler will inline |

Detection quality comes from two places rather than from bigger regexes:

- **Semantic confirmation.** Any JWT matches the Supabase pattern; only one whose
  payload decodes to `"role":"service_role"` is reported. The anon key, which is
  published on purpose, is shaped identically and is never a finding.
- **Stack gating.** Rules declare the stacks they apply to, and the engine skips
  the rest and records why. A Firebase project never sees the RLS rule, and the
  report says so rather than staying silent.

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
  rules/           One module per check. Importing the package registers them.
  explain/         Strictly downstream of detection. Static by default, Claude optional.
  report/          JSON is canonical; HTML renders from it.
  service/         FastAPI. Owns transport and the ownership guardrail, nothing else.
fixtures/
  vulnerable-app/  Vite + React + Supabase, three planted defects.
  clean-app/       Next.js + Supabase, built correctly. Must always come back clean.
```

Adding a check is adding one module in `rules/`: declare `id`, `title`,
`severity`, an `Applicability` gate and your blind spots in `limits`, then
implement `check(ctx) -> Iterable[Finding]`. Nothing else in the system changes.

## The fixture corpus

Two small real applications, not mocks. Every assertion in the suite runs against
files a scanner would actually meet.

`clean-app` is the more valuable of the two and is written to be hard to pass by
accident. It hardcodes a Supabase **anon** key in a client component, commits an
`.env.local` holding three `NEXT_PUBLIC_` variables of which two end in `_KEY`,
and keeps its privileged Stripe call in an `app/api/` route handler. A scanner
that matches on shape alone fires on all three. **If a rule fires on `clean-app`,
the rule is wrong.**

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
| **F3** server-side authorization | Endpoints that check authentication but not *ownership*. Needs call-graph analysis of route handlers, not pattern matching; the parser work is the reason it is not in week one. |
| **F4** public admin surface | Route enumeration plus an unauthenticated request per candidate. Requires the URL-probe ingestion mode and therefore ownership verification first. |
| **S1** webhook signature verification | Detectable statically today: a Stripe/Paddle handler with no `constructEvent`/signature check. Next rule to land. |
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

## Scope statement

Passing this scan does not mean your application is secure. It means the specific
defects in the published ruleset were not found in the code it could read. The
ruleset covers the failure modes that most often breach applications like yours.
It is not a penetration test, it does not evaluate business logic, and it is not a
substitute for a security review.

## License

Apache-2.0.
