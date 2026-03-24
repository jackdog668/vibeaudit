/**
 * Rule: header-injection
 * Detects user input placed in HTTP response headers (CRLF injection).
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const HEADER_SET_PATTERNS = [
  // res.setHeader with user input
  { pattern: /(?:res|response)\.(?:setHeader|header|set)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:req\.|request\.|body\.|params\.|query\.)/gi, label: 'User input in response header value' },
  // res.redirect with user input
  { pattern: /(?:res|response)\.redirect\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)/gi, label: 'User input in redirect Location header' },
  // Set-Cookie with user input
  { pattern: /Set-Cookie.*(?:req\.|request\.|body\.|params\.|query\.)/gi, label: 'User input in Set-Cookie header' },
];

/** @type {Rule} */
export const headerInjection = {
  id: 'header-injection',
  name: 'Header Injection',
  severity: 'warning',
  description: 'Detects user input placed in HTTP response headers (CRLF injection).',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    const findings = [];

    for (const { pattern, label } of HEADER_SET_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'header-injection',
          ruleName: 'Header Injection',
          severity: 'warning',
          message: `${label} — CRLF injection can set arbitrary headers.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Strip \\r\\n from user input before placing in headers: value.replace(/[\\r\\n]/g, ""). Better yet, validate against an allowlist.',
        });
      }
    }

    return findings;
  },
};
