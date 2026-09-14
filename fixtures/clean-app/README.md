# clean-app

A correctly built Next.js + Supabase app. Every rule in the ruleset must pass on
it, and it is written to be hard to pass by accident:

- `components/SupabaseProvider.tsx` hardcodes a Supabase **anon** key. That is
  public by design and safe while row-level security is on, so a scanner that
  reports "a JWT in client code" fails here. Confirming the payload says
  `"role":"anon"` and not `"role":"service_role"` is what distinguishes the two.
- `.env.local` is committed and contains three `NEXT_PUBLIC_` variables, two of
  which end in `_KEY`. All three are publishable values. A name-shape check alone
  would fire; the allowlist of known-public variables is why it does not.
- The privileged Stripe call lives in `app/api/checkout/route.ts`, which is
  server-only. A scanner that treats every file under `app/` as browser code
  would report it.
- Every table in `supabase/migrations/` enables row-level security in the same
  migration that creates it.

If a rule ever fires on this app, the rule is wrong. Fix the rule, not the fixture.
