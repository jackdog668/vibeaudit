/**
 * Rule: secrets-in-urls
 * Detects API keys and tokens passed in URL query parameters.
 *
 * The attack: ?api_key=sk_live_xxx is logged in server access logs,
 * browser history, proxy logs, CDN logs, and sent in the Referer header
 * when you click any external link. Every layer between client and server
 * records the full URL. Your secret is everywhere.
 */

/** @typedef {import('./types.js').Rule} Rule */

const URL_SECRET_PATTERNS = [
  // Constructing URLs with secret query params
  {
    regex: /(?:url|href|src|endpoint|api)\s*[=+:]\s*[^;\n]*\?\s*[^;\n]*(?:api_key|apiKey|secret|token|auth|key|password|access_token)\s*=/gi,
    label: 'Secret passed as URL query parameter — logged in server logs, browser history, and Referer headers',
  },
  // URLSearchParams with secrets
  {
    regex: /searchParams\.(?:set|append)\s*\(\s*['"`](?:api_key|apiKey|secret|token|auth_token|access_token|key|password)['"`]/gi,
    label: 'Secret added to URL search params — visible in all request logs',
  },
  // fetch/axios with secret in URL
  {
    regex: /(?:fetch|axios|got)\s*\(\s*[`'"][^`'"]*[?&](?:api_key|apiKey|secret|token|key|password)=/gi,
    label: 'Secret embedded in fetch URL — logged everywhere the request passes through',
  },
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const secretsInUrls = {
  id: 'secrets-in-urls',
  name: 'Secrets in URLs',
  severity: 'critical',
  description: 'Detects API keys and tokens passed in URL query parameters — visible in logs, browser history, and Referer headers.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label } of URL_SECRET_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'secrets-in-urls',
            ruleName: 'Secrets in URLs',
            severity: 'critical',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Never pass secrets in URL query parameters. Use Authorization headers instead: "headers: { Authorization: 'Bearer ' + token }". URLs are logged in server access logs, proxy logs, CDN logs, browser history, and sent in the Referer header to every external site you link to.`,
          });
        }
      }
    }

    return findings;
  },
};
