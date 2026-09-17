import Stripe from "stripe";

// The correct shape of a Stripe webhook handler, and the control case for S1.
//
// Three things make it correct, and a scanner that misses any of them would
// report this file:
//   1. the raw body is read with request.text(), not request.json() -- parsing
//      first would change the bytes and break the signature
//   2. constructEvent verifies before anything in the payload is trusted
//   3. a bad signature is rejected with 400 and nothing else happens
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function POST(request: Request): Promise<Response> {
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature");

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      rawBody,
      signature as string,
      process.env.STRIPE_WEBHOOK_SECRET as string,
    );
  } catch {
    return new Response("bad signature", { status: 400 });
  }

  // Only reached once the signature checks out, and only `event` is trusted --
  // never the body we read above.
  if (event.type === "checkout.session.completed") {
    // grant access to the purchasing account
  }

  return Response.json({ received: true });
}
