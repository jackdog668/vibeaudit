/**
 * Rule: ldap-injection
 * Detects LDAP queries constructed with unsanitized user input.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const LDAP_PATTERNS = [
  // String concat in LDAP filter
  { pattern: /(?:filter|searchFilter|ldapFilter)\s*[:=]\s*[`'"]\s*\([\s\S]{0,100}\$\{(?:req\.|request\.|body\.|params\.|query\.|input|user)/gi, label: 'User input in LDAP filter (template literal)' },
  { pattern: /(?:filter|searchFilter)\s*[:=]\s*['"].*['"]\s*\+\s*(?:req\.|request\.|body\.|params\.|query\.|input|user)/gi, label: 'User input concatenated into LDAP filter' },
  // ldapjs search with direct input
  { pattern: /\.search\s*\(\s*(?:req\.body|req\.query|req\.params)/gi, label: 'LDAP search with request data as base DN' },
];

/** @type {Rule} */
export const ldapInjection = {
  id: 'ldap-injection',
  name: 'LDAP Injection',
  severity: 'critical',
  description: 'Detects LDAP queries with unsanitized user input.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:ldap|ldapjs|activedirectory)/i.test(file.content)) return [];

    const findings = [];

    for (const { pattern, label } of LDAP_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'ldap-injection',
          ruleName: 'LDAP Injection',
          severity: 'critical',
          message: `${label}.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Escape LDAP special characters in user input: replace *, (, ), \\, NUL, /, with their escaped equivalents. Use parameterized LDAP filters when available.',
        });
      }
    }

    return findings;
  },
};
