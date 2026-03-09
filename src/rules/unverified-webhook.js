/**
 * Rule: unverified-webhook
 * Detects webhook handlers that don't verify the request signature.
 *
 * The attack: Find /api/webhooks/stripe URL. POST a fake
 * "payment_intent.succeeded" event. Server processes it.
 * Free products forever. Or worse: fake refund events that
 * credit attacker accounts.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Patterns indicating a webhook handler. */
const WEBHOOK_HANDLER_PATTERNS = [
  // Route path contains "webhook"
  {
    regex: /(?:app|router|fastify|hono)\.post\s*\(\s*['"`][^'"`]*webhook/gi,
    label: 'Express-style webhook route',
  },
  // Next.js webhook route (file is in webhook path)
  {
    regex: /export\s+(?:async\s+)?function\s+POST\s*\(/g,
    label: 'Next.js POST handler',
    fileOnly: true,  // Only flag if file path suggests webhook
  },
  // Event type checking (strong indicator)
  {
    regex: /(?:event\.type|event\['type'\])\s*(?:===|==)\s*['"`](?:payment_intent|checkout\.session|customer\.|invoice\.|charge\.|order\.|message\.)/gi,
    label: 'Webhook event type processing',
  },
];

/** Patterns that indicate signature verification IS present. */
const VERIFICATION_INDICATORS = [
  // Stripe
  /stripe\.webhooks\.constructEvent/i,
  /constructEvent\s*\(/i,
  /stripe-signature/i,
  /Stripe\.Webhook/i,
  // PayPal
  /paypal.*verify/i,
  /verifyWebhookSignature/i,
  // Twilio
  /twilio.*validate/i,
  /validateRequest/i,
  /X-Twilio-Signature/i,
  // Clerk
  /svix|Webhook\s*\(\s*secret/i,
  // Generic signature verification
  /(?:verifySignature|verify_signature|hmac|createHmac|webhook_secret|WEBHOOK_SECRET|signing_secret|SIGNING_SECRET)/i,
  // Crypto-based verification
  /crypto\.(?:createHmac|timingSafeEqual)/i,
];

/** Only check webhook handler files. */
const WEBHOOK_FILE_PATTERN = /webhook/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const unverifiedWebhook = {
  id: 'unverified-webhook',
  name: 'Unverified Webhook',
  severity: 'critical',
  description: 'Detects webhook handlers that accept events without verifying the request signature — anyone can send fake events.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const isWebhookFile = WEBHOOK_FILE_PATTERN.test(file.relativePath);

    // Find webhook handler patterns.
    let isWebhookHandler = false;
    let handlerLine = 0;
    let handlerEvidence = '';

    for (const { regex, label, fileOnly } of WEBHOOK_HANDLER_PATTERNS) {
      // fileOnly patterns only apply when the file path suggests webhook
      if (fileOnly && !isWebhookFile) continue;

      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        isWebhookHandler = true;
        const upToMatch = file.content.slice(0, match.index);
        handlerLine = upToMatch.split('\n').length;
        handlerEvidence = file.lines[handlerLine - 1]?.trim().slice(0, 120);
        break;
      }
      if (isWebhookHandler) break;
    }

    // If not a webhook handler, and file path doesn't suggest webhooks, skip.
    if (!isWebhookHandler && !isWebhookFile) return [];
    // If it's a webhook file path but we didn't find explicit patterns,
    // still flag it if there's no verification.
    if (!isWebhookHandler && isWebhookFile) {
      // Only flag if it has POST/route handling.
      const hasHandler = /(?:export\s+(?:async\s+)?function\s+POST|\.post\s*\()/i.test(file.content);
      if (!hasHandler) return [];
      handlerLine = 1;
      handlerEvidence = file.relativePath;
    }

    // Check for signature verification.
    const hasVerification = VERIFICATION_INDICATORS.some((p) => p.test(file.content));

    if (hasVerification) return [];

    return [
      {
        ruleId: 'unverified-webhook',
        ruleName: 'Unverified Webhook',
        severity: 'critical',
        message: 'Webhook handler does not verify the request signature. Anyone who knows the URL can send fake events (e.g., fake "payment succeeded").',
        file: file.relativePath,
        line: handlerLine,
        evidence: handlerEvidence,
        fix: `Always verify webhook signatures before processing events. For Stripe: use stripe.webhooks.constructEvent(body, sig, secret). For other providers: verify the HMAC signature using your webhook secret. Without verification, attackers can POST fake events to trigger actions like granting access, issuing refunds, or creating accounts.`,
      },
    ];
  },
};
