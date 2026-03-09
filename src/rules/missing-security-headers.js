/**
 * Rule: missing-security-headers
 * Checks for security header configuration in framework config files.
 * AI-generated apps almost never set these up.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Config files where headers SHOULD be set. */
const CONFIG_FILES = /(?:next\.config\.|vercel\.json|netlify\.toml|nuxt\.config\.|astro\.config\.|vite\.config\.|nginx\.conf|\.htaccess|middleware\.(ts|js))/i;

/** Headers we're looking for evidence of. */
const SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', aliases: ['CSP', 'content-security-policy', 'contentSecurityPolicy'] },
  { name: 'X-Frame-Options', aliases: ['x-frame-options', 'xFrameOptions'] },
  { name: 'X-Content-Type-Options', aliases: ['x-content-type-options', 'xContentTypeOptions'] },
  { name: 'Strict-Transport-Security', aliases: ['HSTS', 'strict-transport-security'] },
  { name: 'Referrer-Policy', aliases: ['referrer-policy', 'referrerPolicy'] },
];

/** @type {Rule} */
export const missingSecurityHeaders = {
  id: 'missing-security-headers',
  name: 'Missing Security Headers',
  severity: 'warning',
  description: 'Checks framework config and middleware files for security header configuration.',

  check(file) {
    if (!CONFIG_FILES.test(file.relativePath)) return [];

    const findings = [];
    const contentLower = file.content.toLowerCase();

    const missing = SECURITY_HEADERS.filter((header) => {
      const allNames = [header.name.toLowerCase(), ...header.aliases.map((a) => a.toLowerCase())];
      return !allNames.some((name) => contentLower.includes(name));
    });

    if (missing.length > 0) {
      const missingNames = missing.map((h) => h.name).join(', ');
      findings.push({
        ruleId: 'missing-security-headers',
        ruleName: 'Missing Security Headers',
        severity: 'warning',
        message: `Config file is missing security headers: ${missingNames}`,
        file: file.relativePath,
        line: 1,
        evidence: `Missing: ${missingNames}`,
        fix: `Add security headers to your deployment config or middleware. At minimum set: Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security, and Referrer-Policy: strict-origin-when-cross-origin.`,
      });
    }

    return findings;
  },
};
