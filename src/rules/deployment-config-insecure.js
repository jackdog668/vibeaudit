/**
 * Rule: deployment-config-insecure
 * Detects insecure settings in vercel.json, netlify.toml, and similar
 * deployment configuration files.
 */

/** @typedef {import('./types.js').Rule} Rule */

const CONFIG_FILES = /(?:vercel\.json|netlify\.toml|firebase\.json|fly\.toml)$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/** @type {Rule} */
export const deploymentConfigInsecure = {
  id: 'deployment-config-insecure',
  name: 'Deployment Config Insecure',
  severity: 'warning',
  description: 'Detects insecure settings in deployment configuration files.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!CONFIG_FILES.test(file.relativePath)) return [];

    const findings = [];

    // Check for missing security headers in vercel.json
    if (/vercel\.json/i.test(file.relativePath)) {
      const hasHeaders = /headers/i.test(file.content);
      if (!hasHeaders) {
        findings.push({
          ruleId: 'deployment-config-insecure',
          ruleName: 'Deployment Config Insecure',
          severity: 'warning',
          message: 'vercel.json has no security headers configured.',
          file: file.relativePath,
          line: 1,
          fix: 'Add a "headers" section with X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.',
        });
      }

      // CORS wildcard
      if (/Access-Control-Allow-Origin.*\*/i.test(file.content)) {
        const lineIdx = file.lines.findIndex((l) => /Access-Control-Allow-Origin.*\*/.test(l));
        findings.push({
          ruleId: 'deployment-config-insecure',
          ruleName: 'Deployment Config Insecure',
          severity: 'warning',
          message: 'CORS wildcard (*) allows any website to make requests to your API.',
          file: file.relativePath,
          line: lineIdx >= 0 ? lineIdx + 1 : 1,
          evidence: file.lines[lineIdx]?.trim().slice(0, 120),
          fix: 'Replace * with your specific domain(s).',
        });
      }
    }

    // Check for public directory listings in netlify.toml
    if (/netlify\.toml/i.test(file.relativePath)) {
      if (!/X-Frame-Options/i.test(file.content) && !/Content-Security-Policy/i.test(file.content)) {
        findings.push({
          ruleId: 'deployment-config-insecure',
          ruleName: 'Deployment Config Insecure',
          severity: 'warning',
          message: 'netlify.toml has no security headers configured.',
          file: file.relativePath,
          line: 1,
          fix: 'Add [[headers]] sections with security headers: X-Frame-Options, X-Content-Type-Options, CSP.',
        });
      }
    }

    return findings;
  },
};
