/**
 * Rule: nextjs-api-route-no-method-check
 * Detects Next.js Pages Router API routes that don't check req.method,
 * allowing all HTTP methods through a single handler.
 */

/** @typedef {import('./types.js').Rule} Rule */

const PAGES_API = /pages\/api\//i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/** @type {Rule} */
export const nextjsApiRouteNoMethodCheck = {
  id: 'nextjs-api-route-no-method-check',
  name: 'Next.js API Route No Method Check',
  severity: 'warning',
  description: 'Detects Next.js Pages Router API routes that accept all HTTP methods.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!PAGES_API.test(file.relativePath)) return [];

    // Only applies to Pages Router default exports (App Router uses named exports)
    const hasDefaultExport = /export\s+default\s+(?:async\s+)?function/i.test(file.content);
    if (!hasDefaultExport) return [];

    const checksMethod = /req\.method\s*[!=]==?\s*['"`]|switch\s*\(\s*req\.method\s*\)|method\s*===?\s*['"`](?:GET|POST|PUT|PATCH|DELETE)/i.test(file.content);
    if (checksMethod) return [];

    const lineIdx = file.lines.findIndex((l) => /export\s+default/.test(l));

    return [{
      ruleId: 'nextjs-api-route-no-method-check',
      ruleName: 'Next.js API Route No Method Check',
      severity: 'warning',
      message: 'Pages API route handles all HTTP methods without checking req.method.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Add a method check: if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" }).',
    }];
  },
};
