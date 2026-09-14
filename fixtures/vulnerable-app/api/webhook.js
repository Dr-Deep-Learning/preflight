// Server-side file. S2 must not report anything found in here as client-exposed.
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export default async function handler(req, res) {
  const event = JSON.parse(req.body);
  res.json({ received: true, type: event.type });
}
