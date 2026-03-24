/**
 * Rule: regex-dos
 * Detects regex patterns vulnerable to catastrophic backtracking (ReDoS).
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.d\.ts$)/i;
const SKIP_RULES = /src\/rules\//i;

// Heuristic patterns that indicate potentially dangerous regexes
const REDOS_INDICATORS = [
  // Nested quantifiers: (a+)+, (a*)*
  /\([^)]*[+*][^)]*\)[+*]/,
  // Overlapping alternation with quantifiers
  /\([^)]*\|[^)]*\)[+*]/,
  // Multiple quantifiers on character classes
  /\[[^\]]+\][+*][+*]/,
];

/** @type {Rule} */
export const regexDos = {
  id: 'regex-dos',
  name: 'Regex DoS (ReDoS)',
  severity: 'warning',
  description: 'Detects regex patterns vulnerable to catastrophic backtracking.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];

    const findings = [];

    // Find regex literals and new RegExp() calls
    const regexPattern = /(?:\/([^/\n]+)\/[gimsuvy]*|new\s+RegExp\s*\(\s*['"`]([^'"`\n]+)['"`])/g;
    regexPattern.lastIndex = 0;

    let match;
    while ((match = regexPattern.exec(file.content)) !== null) {
      const regexBody = match[1] || match[2];
      if (!regexBody) continue;

      for (const indicator of REDOS_INDICATORS) {
        if (indicator.test(regexBody)) {
          const lineNum = file.content.slice(0, match.index).split('\n').length;
          const line = file.lines[lineNum - 1]?.trim();
          if (line?.startsWith('//') || line?.startsWith('*')) continue;

          findings.push({
            ruleId: 'regex-dos',
            ruleName: 'Regex DoS (ReDoS)',
            severity: 'warning',
            message: 'Regex with nested quantifiers may cause catastrophic backtracking on malicious input.',
            file: file.relativePath,
            line: lineNum,
            evidence: line?.slice(0, 120),
            fix: 'Simplify the regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers if supported. Add input length limits before regex matching. Consider using a regex linter like safe-regex.',
          });
          break;
        }
      }
    }

    return findings;
  },
};
