/**
 * Rule: console-data-leak
 * Detects console.log statements that output sensitive data.
 *
 * The DevTools attack: Open Console tab → all your debug logs are right there.
 * "console.log('user:', user)" just handed someone the full user object.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** console.log patterns that output sensitive-looking data. */
const SENSITIVE_LOG_PATTERNS = [
  // Logging tokens, secrets, passwords
  {
    regex: /console\.(?:log|info|debug|warn)\s*\([^)]*(?:token|jwt|secret|password|passwd|credential|apiKey|api_key|authorization|bearer|session_id)/gi,
    label: 'Sensitive data in console.log — visible in DevTools Console',
    severity: 'warning',
  },
  // Logging full request/response objects
  {
    regex: /console\.(?:log|info|debug)\s*\([^)]*(?:req\.body|req\.headers|request\.body|request\.headers|response\.data|res\.data)/gi,
    label: 'Request/response data logged — may expose auth headers or PII in DevTools Console',
    severity: 'warning',
  },
  // Logging user objects
  {
    regex: /console\.(?:log|info|debug)\s*\([^)]*(?:['"`]user|currentUser|userData|userInfo|profile)/gi,
    label: 'User data logged to console — visible in DevTools',
    severity: 'info',
  },
];

/** Skip test files and server-only files. */
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|__mocks__)/i;

/** @type {Rule} */
export const consoleDataLeak = {
  id: 'console-data-leak',
  name: 'Console Data Leaks',
  severity: 'warning',
  description: 'Detects console.log statements that output sensitive data — all visible in DevTools Console tab.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, severity } of SENSITIVE_LOG_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'console-data-leak',
            ruleName: 'Console Data Leaks',
            severity,
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Remove console.log statements that output sensitive data before deploying. Use a proper logging library with log levels and strip debug/info logs in production builds. Anyone can open DevTools → Console and see everything you logged.`,
          });
        }
      }
    }

    return findings;
  },
};
