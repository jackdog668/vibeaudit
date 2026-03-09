/**
 * Rule: missing-csrf
 * Detects forms and state-changing API routes with no CSRF protection.
 *
 * The attack: Attacker emails your user a link to evil.com.
 * That page has a hidden form that auto-submits a POST to YOUR app.
 * Browser sends cookies automatically. User's account gets modified
 * without them clicking anything on your site.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** State-changing route handlers that need CSRF protection. */
const STATE_CHANGING_ROUTES = [
  // Express/Hono/Fastify POST/PUT/PATCH/DELETE handlers
  {
    regex: /(?:app|router|fastify|hono)\.(post|put|patch|delete)\s*\(\s*['"`]/gi,
    label: 'State-changing route with no CSRF protection',
  },
  // Next.js App Router mutation handlers
  {
    regex: /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\s*\(/g,
    label: 'Next.js mutation handler — verify CSRF protection is in place',
  },
];

/** CSRF protection indicators. */
const CSRF_INDICATORS = [
  /csrf/i,
  /xsrf/i,
  /csrfToken/i,
  /csurf/i,
  /x-csrf-token/i,
  /x-xsrf-token/i,
  /SameSite\s*[:=]\s*['"`](?:Strict|Lax)['"`]/i,
  /(?:lusca|helmet\.csrf|express-csrf|csrf-csrf)/i,
  // Next.js Server Actions have built-in CSRF
  /['"`]use server['"`]/,
  // Double-submit cookie pattern
  /(?:csrfCookie|csrf_cookie|anti-csrf)/i,
  // Origin/Referer header validation
  /(?:origin|referer)\s*(?:===|!==|==|!=)\s*(?:['"`]|allowed|expected)/i,
];

/** Only check server-side files. */
const SERVER_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/|middleware)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const missingCsrf = {
  id: 'missing-csrf',
  name: 'Missing CSRF Protection',
  severity: 'warning',
  description: 'Detects state-changing routes (POST/PUT/DELETE) with no CSRF protection — vulnerable to cross-site request forgery.',

  check(file) {
    if (!SERVER_FILES.test(file.relativePath)) return [];
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    // Check if file has CSRF indicators anywhere.
    const hasCsrf = CSRF_INDICATORS.some((p) => p.test(file.content));
    if (hasCsrf) return [];

    const findings = [];

    for (const { regex, label } of STATE_CHANGING_ROUTES) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        const upToMatch = file.content.slice(0, match.index);
        const lineNum = upToMatch.split('\n').length;

        findings.push({
          ruleId: 'missing-csrf',
          ruleName: 'Missing CSRF Protection',
          severity: 'warning',
          message: label,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: `Add CSRF protection to state-changing endpoints. Options: (1) Use SameSite=Lax or Strict cookies. (2) Implement double-submit cookie pattern. (3) Check Origin/Referer headers. (4) Use a CSRF token library like csrf-csrf. Without CSRF protection, attackers can trigger actions on behalf of your users from external sites.`,
        });
      }
    }

    return findings;
  },
};
