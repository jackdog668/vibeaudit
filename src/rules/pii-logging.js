/**
 * Rule: pii-logging
 * Detects PII (emails, phone numbers, SSNs) in console.log or logger calls.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.d\.ts$)/i;

const LOG_CALL = /(?:console\.(?:log|info|debug|warn|error)|logger\.(?:info|debug|warn|error|log))\s*\(/g;

const PII_VARS = /(?:email|phone|ssn|socialSecurity|dateOfBirth|dob|creditCard|cardNumber|address|firstName|lastName|fullName|passport|driversLicense|nationalId)(?:\b|[A-Z])/i;

/** @type {Rule} */
export const piiLogging = {
  id: 'pii-logging',
  name: 'PII Logging',
  severity: 'warning',
  description: 'Detects personally identifiable information in logging statements.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (!LOG_CALL.test(line)) {
        LOG_CALL.lastIndex = 0;
        continue;
      }
      LOG_CALL.lastIndex = 0;

      if (PII_VARS.test(line)) {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

        findings.push({
          ruleId: 'pii-logging',
          ruleName: 'PII Logging',
          severity: 'warning',
          message: 'Logging statement may contain personally identifiable information (PII).',
          file: file.relativePath,
          line: i + 1,
          evidence: trimmed.slice(0, 120),
          fix: 'Remove PII from log statements or redact sensitive fields before logging. Use structured logging with field allowlists.',
        });
      }
    }

    return findings;
  },
};
