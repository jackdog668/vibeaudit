/**
 * Rule: netlify-redirect-open
 * Detects open redirect/proxy patterns in Netlify _redirects and netlify.toml.
 */

/** @typedef {import('./types.js').Rule} Rule */

const NETLIFY_FILES = /(?:_redirects|netlify\.toml)$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/** @type {Rule} */
export const netlifyRedirectOpen = {
  id: 'netlify-redirect-open',
  name: 'Netlify Open Redirect',
  severity: 'warning',
  description: 'Detects open redirect or proxy patterns in Netlify configuration.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!NETLIFY_FILES.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i].trim();
      if (line.startsWith('#') || !line) continue;

      // Detect wildcard proxy rules: /api/*  https://external.com/:splat  200
      if (/\/\*\s+https?:\/\/.*:splat\s+200/.test(line)) {
        findings.push({
          ruleId: 'netlify-redirect-open',
          ruleName: 'Netlify Open Redirect',
          severity: 'warning',
          message: 'Wildcard proxy rule forwards all requests to an external service — potential open proxy.',
          file: file.relativePath,
          line: i + 1,
          evidence: line.slice(0, 120),
          fix: 'Narrow the proxy rule to specific paths instead of wildcards. Verify the target domain is trusted.',
        });
      }

      // Detect redirect with :splat to external URL
      if (/\/:splat\s+https?:\/\//.test(line) || /\/\*\s+https?:\/\//.test(line)) {
        if (!/200/.test(line)) {
          findings.push({
            ruleId: 'netlify-redirect-open',
            ruleName: 'Netlify Open Redirect',
            severity: 'warning',
            message: 'Wildcard redirect to external URL — may be used for phishing.',
            file: file.relativePath,
            line: i + 1,
            evidence: line.slice(0, 120),
            fix: 'Restrict redirects to your own domains. Use specific paths instead of wildcards.',
          });
        }
      }
    }

    return findings;
  },
};
