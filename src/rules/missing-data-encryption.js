/**
 * Rule: missing-data-encryption
 * Detects sensitive data stored in databases without encryption.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const SENSITIVE_FIELD_NAMES = /(?:ssn|socialSecurity|creditCard|cardNumber|taxId|bankAccount|routingNumber|driversLicense|passport|nationalId)/i;

const DB_WRITE_PATTERNS = [
  /\.create\s*\(\s*\{[\s\S]{0,500}(?:ssn|socialSecurity|creditCard|cardNumber|taxId|bankAccount)/gi,
  /\.insert\s*\(\s*\{[\s\S]{0,500}(?:ssn|socialSecurity|creditCard|cardNumber|taxId|bankAccount)/gi,
  /\.update\s*\(\s*\{[\s\S]{0,500}(?:ssn|socialSecurity|creditCard|cardNumber|taxId|bankAccount)/gi,
  /(?:INSERT|UPDATE)\s+.*(?:ssn|social_security|credit_card|card_number|tax_id|bank_account)/gi,
];

/** @type {Rule} */
export const missingDataEncryption = {
  id: 'missing-data-encryption',
  name: 'Missing Data Encryption',
  severity: 'warning',
  description: 'Detects sensitive data (SSN, credit card, etc.) stored without encryption.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    const findings = [];

    for (const pattern of DB_WRITE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        // Check if encryption is happening near this code
        const context = file.content.slice(Math.max(0, match.index - 300), match.index + match[0].length + 300);
        if (/encrypt|cipher|crypto\.create|aes|bcrypt|hash/i.test(context)) continue;

        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'missing-data-encryption',
          ruleName: 'Missing Data Encryption',
          severity: 'warning',
          message: 'Sensitive data stored in database without apparent encryption.',
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Encrypt sensitive fields (SSN, credit cards, etc.) before storing. Use AES-256-GCM: crypto.createCipheriv("aes-256-gcm", key, iv). Store encrypted text + IV. Decrypt on read.',
        });
      }
    }

    return findings;
  },
};
