import Stripe from "stripe";

// Server-only: this file never reaches the browser, and the key is read from
// the environment rather than written down.
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function POST(request: Request): Promise<Response> {
  const { priceId } = await request.json();
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: "https://example.test/done",
    cancel_url: "https://example.test/cancel",
  });
  return Response.json({ url: session.url });
}
