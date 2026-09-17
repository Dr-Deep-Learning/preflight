# Fixture corpus

Two small applications that exist so the test suite asserts real detections
against real code instead of against mocks.

| App | Stack | Expected outcome |
|---|---|---|
| `vulnerable-app/` | Vite + React + Supabase + Stripe | F1, F2, S1 and S2 all fire |
| `clean-app/` | Next.js + Supabase + Stripe | every rule passes |

`clean-app` is the more valuable of the two. Any scanner can find a secret; the
thing that decides whether a report is trustworthy is whether a correctly built
app comes back clean. It deliberately contains things that *look* like findings
and are not — a hardcoded Supabase **anon** key (public by design), a
`NEXT_PUBLIC_` variable holding a publishable Stripe key, an `.env.example` full
of realistic-looking values — so a regression toward over-reporting fails a test.

## Every secret in here is synthetic

The JWTs are unsigned, the connection strings point at a domain that does not
exist, and the API keys are shaped like the real thing but are not valid with any
provider. They are committed on purpose: a `.env` that git is not tracking cannot
reproduce the defect the F2 rule is about, so `.gitignore` has explicit negations
for `fixtures/**/.env`.

If GitHub push protection ever flags one of these, replace the value rather than
weakening the rule — the rules match on shape and on semantic confirmation (a JWT
is only a service-role key if its payload says `"role":"service_role"`), so any
correctly shaped replacement works.

## Rule of the corpus

Never add a fixture without adding the assertion it exists to support, and never
weaken a rule to make a fixture pass. If a rule fires on `clean-app`, the rule is
wrong.
