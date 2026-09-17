# vulnerable-app

A deliberately broken Vite + React + Supabase app, of the kind an AI builder
produces in an afternoon. Planted defects, in the order a report should rank them:

1. **F2** — the Supabase service-role key is hardcoded in `src/lib/supabaseClient.ts`
   and also sits in a committed `.env`, alongside a Postgres connection string.
2. **F1** — `supabase/migrations/` creates `profiles`, `messages` and
   `subscriptions` with no row-level security. `messages` even has a policy, which
   does nothing at all because RLS was never enabled on it. `waitlist` is done
   correctly and must not be reported.
3. **S2** — an OpenAI-style key is written into `src/components/Chat.tsx`, and the
   same key is exposed a second way through a `VITE_`-prefixed environment
   variable, which Vite inlines into the browser bundle at build time.
4. **S1** — `api/webhook.js` parses `req.body` straight into an event and never
   calls `stripe.webhooks.constructEvent`, so anyone can POST a forged
   `checkout.session.completed` to it.

`package.json` declares `stripe` because S1 is gated on a detected payment
provider. It was missing at first, which meant the rule skipped the very file it
exists to catch — the fixture was unrealistic, not the gate: an app that imports
Stripe without depending on it would not build.

Nothing here is a real credential. See `../README.md`.
