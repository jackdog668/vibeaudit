/**
 * Rule: stripe-webhook-no-verify
 * Detects Stripe webhook handlers that don't verify the webhook signature
 * using stripe.webhooks.constructEvent().
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;
const WEBHOOK_FILE = /(?:webhook|stripe|payment)/i;

/** @type {Rule} */
export const stripeWebhookNoVerify = {
  id: 'stripe-webhook-no-verify',
  name: 'Stripe Webhook No Verification',
  severity: 'critical',
  description: 'Detects Stripe webhook handlers without signature verification.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!WEBHOOK_FILE.test(file.relativePath) && !/stripe/i.test(file.content)) return [];

    // Does the file handle Stripe webhook events?
    const hasStripeEvent = /(?:event\.type|type\s*===?\s*['"](?:checkout\.session|payment_intent|invoice|customer\.subscription))/i.test(file.content);
    const hasStripeWebhook = /stripe.*webhook|webhook.*stripe/i.test(file.content);
    if (!hasStripeEvent && !hasStripeWebhook) return [];

    // Check for constructEvent
    const hasVerification = /constructEvent|webhooks\.construct/i.test(file.content);
    if (hasVerification) return [];

    // Find the webhook handler line
    const lineIdx = file.lines.findIndex((l) =>
      /event\.type|checkout\.session|payment_intent/i.test(l)
    );

    return [{
      ruleId: 'stripe-webhook-no-verify',
      ruleName: 'Stripe Webhook No Verification',
      severity: 'critical',
      message: 'Stripe webhook handler does not verify the signature — anyone can send fake events.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Verify the webhook: const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET). Never parse the body as JSON first — use the raw body.',
    }];
  },
};
