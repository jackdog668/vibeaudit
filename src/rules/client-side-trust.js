/**
 * Rule: client-side-trust
 * Detects business logic that trusts client-side values without server validation.
 *
 * The DevTools attack: Open Console → change the price variable → submit the form.
 * Or intercept the fetch request in Network tab → edit the body → resend.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Patterns where business-critical values are computed or validated client-side only. */
const CLIENT_TRUST_PATTERNS = [
  // Price/total calculation assigned from arithmetic in client code
  {
    regex: /(?:totalPrice|total_price|cartTotal|cart_total|orderTotal|order_total|subTotal|sub_total|grandTotal|finalPrice|discountedPrice)\s*=\s*[^;\n]*(?:\*|\+|reduce|\.map|\.forEach|parseFloat|parseInt)/gi,
    label: 'Price/total calculated client-side with arithmetic — can be modified via DevTools Console before submission',
  },
  // Discount percentage/amount applied client-side with arithmetic
  {
    regex: /(?:discountAmount|discountedTotal|discountValue|promoDiscount)\s*=\s*[^;\n]*(?:\*|\-|\/|percent|rate)/gi,
    label: 'Discount calculation runs client-side — can be manipulated in DevTools',
  },
  // Hidden form fields for sensitive data
  {
    regex: /type\s*=\s*['"`]hidden['"`][^>]*(?:name|id)\s*=\s*['"`](?:price|amount|total|role|admin|userId|user_id|permission)/gi,
    label: 'Sensitive data in hidden form field — trivially editable via DevTools Elements tab',
  },
  // Disabled button with sensitive action
  {
    regex: /disabled\s*=\s*\{[^}]*(?:isAdmin|hasPermission|isOwner|canDelete|canEdit|isAuthorized)/gi,
    label: 'Button disabled based on client-side permission check — button can be re-enabled in DevTools Elements',
    severity: 'info',
  },
];

/** Only check client-side files. */
const CLIENT_FILES = /\.(?:jsx|tsx|vue|svelte|html|htm)$|(?:^src\/(?:components|pages|app|views))/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const clientSideTrust = {
  id: 'client-side-trust',
  name: 'Client-Side Trust',
  severity: 'warning',
  description: 'Detects business logic (pricing, permissions, validation) that only runs client-side and can be manipulated via DevTools.',

  check(file) {
    if (!CLIENT_FILES.test(file.relativePath)) return [];
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('{/*')) continue;

      for (const { regex, label, severity } of CLIENT_TRUST_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'client-side-trust',
            ruleName: 'Client-Side Trust',
            severity: severity || 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Never trust client-side values for pricing, permissions, or business logic. Always recalculate/revalidate on the server. The client is the user's machine — they control everything on it. DevTools lets anyone modify any value, re-enable any button, and edit any request before it's sent.`,
          });
        }
      }
    }

    return findings;
  },
};
