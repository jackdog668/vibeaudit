/**
 * Rule: hardcoded-credentials
 * Detects hardcoded passwords, connection strings, and credential patterns.
 */

/** @typedef {import('./types.js').Rule} Rule */

const CREDENTIAL_PATTERNS = [
  // password = "something" or password: "something"
  {
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"`](?![\s'"`${}])[^'"`\n]{4,}['"`]/gi,
    label: 'Hardcoded password',
  },
  // Database connection strings with embedded credentials
  {
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^/\s]+:[^@/\s]+@[^/\s]+/gi,
    label: 'Database connection string with credentials',
  },
  // Bearer tokens hardcoded
  {
    regex: /['"`]Bearer\s+[A-Za-z0-9_-]{20,}['"`]/g,
    label: 'Hardcoded bearer token',
  },
  // Basic auth headers
  {
    regex: /['"`]Basic\s+[A-Za-z0-9+/=]{10,}['"`]/g,
    label: 'Hardcoded basic auth header',
  },
];

/** Ignore test files and fixtures — hardcoded creds there are expected. */
const TEST_FILE_PATTERN = /(?:__tests__|__mocks__|\.test\.|\.spec\.|\.mock\.|test\/fixtures|tests\/fixtures)/i;

/** Ignore lines that are clearly template/placeholder values. */
const PLACEHOLDER_VALUES = /(?:your[_-]?password|changeme|placeholder|example|xxx+|todo|fixme|replace[_-]?me)/i;

function isCommentOrDoc(line) {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('<!--')
  );
}

function redactConnection(str) {
  // Redact the password portion of connection strings.
  return str.replace(/:([^@:]+)@/, ':***@');
}

/** @type {Rule} */
export const hardcodedCredentials = {
  id: 'hardcoded-credentials',
  name: 'Hardcoded Credentials',
  severity: 'critical',
  description: 'Detects passwords, connection strings, and auth tokens hardcoded in source files.',

  check(file) {
    if (TEST_FILE_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (isCommentOrDoc(line)) continue;

      for (const { regex, label } of CREDENTIAL_PATTERNS) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(line)) !== null) {
          const matchedText = match[0];

          // Skip placeholder values.
          if (PLACEHOLDER_VALUES.test(matchedText)) continue;

          findings.push({
            ruleId: 'hardcoded-credentials',
            ruleName: 'Hardcoded Credentials',
            severity: 'critical',
            message: `${label} detected.`,
            file: file.relativePath,
            line: i + 1,
            evidence: label.includes('connection')
              ? redactConnection(matchedText)
              : '***REDACTED***',
            fix: `Move credentials to environment variables. Use process.env or a secrets manager. Never store passwords or connection strings in source code.`,
          });
        }
      }
    }

    return findings;
  },
};
