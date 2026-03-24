/**
 * Rule: subdomain-takeover
 * Detects CNAME records or subdomain references pointing to services
 * that may be deprovisioned (S3, Heroku, GitHub Pages, etc.).
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const DNS_FILES = /(?:dns|domain|cname|route53|cloudflare)/i;
const CONFIG_FILES = /(?:\.json|\.yaml|\.yml|\.toml|\.tf)$/i;

const TAKEOVER_TARGETS = [
  /\.s3\.amazonaws\.com/gi,
  /\.s3-website[.-]/gi,
  /\.herokuapp\.com/gi,
  /\.ghost\.io/gi,
  /\.myshopify\.com/gi,
  /\.surge\.sh/gi,
  /\.bitbucket\.io/gi,
  /\.pantheonsite\.io/gi,
  /\.zendesk\.com/gi,
  /\.teamwork\.com/gi,
  /\.helpjuice\.com/gi,
  /\.helpscoutdocs\.com/gi,
  /\.feedpress\.me/gi,
  /\.freshdesk\.com/gi,
  /\.unbounce\.com/gi,
  /\.tictail\.com/gi,
];

/** @type {Rule} */
export const subdomainTakeover = {
  id: 'subdomain-takeover',
  name: 'Subdomain Takeover Risk',
  severity: 'warning',
  description: 'Detects CNAME/subdomain references to services vulnerable to takeover.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!DNS_FILES.test(file.relativePath) && !CONFIG_FILES.test(file.relativePath)) return [];

    const findings = [];

    for (const pattern of TAKEOVER_TARGETS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'subdomain-takeover',
          ruleName: 'Subdomain Takeover Risk',
          severity: 'warning',
          message: `CNAME/reference to ${match[0]} — verify this service is still provisioned.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Verify the target service is still active. If deprovisioned, remove the DNS record to prevent subdomain takeover attacks.',
        });
      }
    }

    return findings;
  },
};
