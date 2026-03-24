/**
 * Rule: nosql-injection
 * Detects MongoDB NoSQL injection via $where, $gt, or user-controlled
 * query operators passed from request objects.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const NOSQL_PATTERNS = [
  // $where with user input
  { pattern: /\$where\s*:\s*(?:req\.|request\.|body\.|params\.|query\.)/gi, label: '$where with user input — arbitrary JavaScript execution' },
  // Direct req.body/query passed as MongoDB query
  { pattern: /\.find\s*\(\s*(?:req\.body|req\.query|request\.body)/gi, label: 'Request body passed directly as MongoDB query — operator injection' },
  { pattern: /\.findOne\s*\(\s*(?:req\.body|req\.query|request\.body)/gi, label: 'Request body passed directly as MongoDB findOne — operator injection' },
  { pattern: /\.deleteMany\s*\(\s*(?:req\.body|req\.query|request\.body)/gi, label: 'Request body passed directly as MongoDB deleteMany — mass deletion' },
  { pattern: /\.updateMany\s*\(\s*(?:req\.body|req\.query|request\.body)/gi, label: 'Request body passed directly as MongoDB updateMany — mass update' },
];

/** @type {Rule} */
export const nosqlInjection = {
  id: 'nosql-injection',
  name: 'NoSQL Injection',
  severity: 'critical',
  description: 'Detects MongoDB NoSQL injection via query operator injection or $where.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:mongo|mongoose|\.find|\.findOne|\$where)/i.test(file.content)) return [];

    const findings = [];

    for (const { pattern, label } of NOSQL_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'nosql-injection',
          ruleName: 'NoSQL Injection',
          severity: 'critical',
          message: `${label}.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Never pass raw request data as MongoDB query. Validate and sanitize input: extract specific fields, cast types explicitly, and strip any keys starting with "$".',
        });
      }
    }

    return findings;
  },
};
