/**
 * Rule: cors-credentials
 * Detects CORS configured with credentials:true and hardcoded/dev origins.
 *
 * The attack: credentials:true + origin:"http://localhost:3000" ships to prod.
 * Or worse: origin reflected from request without validation + credentials:true.
 * Attacker's site makes authenticated requests as your users.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** CORS with credentials patterns. */
const CORS_CRED_PATTERNS = [
  // credentials: true with hardcoded localhost origin
  {
    regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]http:\/\/localhost[^'"`]*['"`][^}]*credentials\s*:\s*true/gis,
    label: 'CORS allows credentials from localhost — will fail in production or expose dev endpoints',
  },
  {
    regex: /cors\s*\(\s*\{[^}]*credentials\s*:\s*true[^}]*origin\s*:\s*['"`]http:\/\/localhost[^'"`]*['"`]/gis,
    label: 'CORS allows credentials from localhost — will fail in production or expose dev endpoints',
  },
  // credentials: true with origin reflecting request
  {
    regex: /origin\s*:\s*(?:req\.headers\.origin|req\.header\s*\(\s*['"`]origin['"`]\s*\))/gi,
    label: 'CORS reflects request origin with no validation — any site can make authenticated requests',
    checkCredentials: true,
  },
  // credentials: true with wildcard (technically browsers block this, but devs try it)
  {
    regex: /origin\s*:\s*(?:true|\*)[^}]*credentials\s*:\s*true/gis,
    label: 'CORS with origin:true/wildcard and credentials — extremely dangerous configuration',
  },
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const corsCredentials = {
  id: 'cors-credentials',
  name: 'CORS with Credentials',
  severity: 'warning',
  description: 'Detects CORS configured with credentials:true and hardcoded, reflected, or overly permissive origins.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    if (!file.content.includes('cors') && !file.content.includes('CORS') && !file.content.includes('Access-Control')) return [];

    const findings = [];

    // Check full content for multi-line CORS configs.
    for (const { regex, label, checkCredentials } of CORS_CRED_PATTERNS) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        // For reflected origin, only flag if credentials is also true.
        if (checkCredentials && !/credentials\s*:\s*true/i.test(file.content)) continue;

        const upToMatch = file.content.slice(0, match.index);
        const lineNum = upToMatch.split('\n').length;

        findings.push({
          ruleId: 'cors-credentials',
          ruleName: 'CORS with Credentials',
          severity: 'warning',
          message: label,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: `When using credentials:true, the origin must be an explicit allowlist of your production domains — never localhost, never reflected from the request, never a wildcard. Use an environment variable for the origin: origin: process.env.CORS_ORIGIN. With credentials:true, a misconfigured origin lets any site make authenticated requests as your users.`,
        });
      }
    }

    return findings;
  },
};
