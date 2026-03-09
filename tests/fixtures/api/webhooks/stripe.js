// Fixture: Unverified Stripe webhook handler
export async function POST(req) {
  const event = await req.json();

  if (event.type === "payment_intent.succeeded") {
    const userId = event.data.object.metadata.userId;
    await grantPremiumAccess(userId);
  }

  if (event.type === "customer.subscription.deleted") {
    await revokePremiumAccess(event.data.object.metadata.userId);
  }

  return Response.json({ received: true });
}
