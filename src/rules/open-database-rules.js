/**
 * Rule: open-database-rules
 * Detects overly permissive Firebase/Firestore/Storage security rules.
 * This is the #1 vibe-code database mistake.
 */

/** @typedef {import('./types.js').Rule} Rule */

const DANGEROUS_RULE_PATTERNS = [
  // Firestore: allow read, write: if true
  {
    regex: /allow\s+(?:read|write|get|list|create|update|delete)[^;]*:\s*if\s+true\s*;/gi,
    label: 'Rule allows unrestricted access (if true)',
  },
  // Firestore: allow read, write without any condition
  {
    regex: /allow\s+(?:read|write|get|list|create|update|delete)\s*;/gi,
    label: 'Rule allows access with no condition at all',
  },
  // RTDB: ".read": true or ".write": true
  {
    regex: /['"]\.(read|write)['"]\s*:\s*['"]?true['"]?/gi,
    label: 'Realtime Database rule is fully open',
  },
  // Storage: allow read, write: if true
  {
    regex: /allow\s+read\s*,\s*write\s*:\s*if\s+true/gi,
    label: 'Storage rules allow unrestricted access',
  },
  // Wildcard match at root level with no auth
  {
    regex: /match\s+\/\{document=\*\*\}\s*\{[^}]*allow\s+read\s*,\s*write/gi,
    label: 'Wildcard match at root with read/write — extremely dangerous',
  },
];

/** Only check files that could contain security rules. */
const RULES_FILES = /(?:firestore\.rules|storage\.rules|database\.rules\.json|\.rules$)/i;
const RULES_CONTENT = /(?:service\s+cloud\.firestore|service\s+firebase\.storage|"rules"|allow\s+read)/i;

/** @type {Rule} */
export const openDatabaseRules = {
  id: 'open-database-rules',
  name: 'Open Database Rules',
  severity: 'critical',
  description: 'Detects Firebase/Firestore/Storage rules that allow unrestricted public access.',

  check(file) {
    const isRulesFile = RULES_FILES.test(file.relativePath);
    const hasRulesContent = RULES_CONTENT.test(file.content);
    if (!isRulesFile && !hasRulesContent) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];

      // Skip JS/TS comments — rules in .rules files don't start with //.
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      for (const { regex, label } of DANGEROUS_RULE_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'open-database-rules',
            ruleName: 'Open Database Rules',
            severity: 'critical',
            message: `${label}. Anyone on the internet can read/write your data.`,
            file: file.relativePath,
            line: i + 1,
            evidence: line.trim(),
            fix: `Require authentication: "allow read, write: if request.auth != null;" at minimum. Better: add granular per-collection rules that validate request.auth.uid matches the document owner.`,
          });
        }
      }
    }

    return findings;
  },
};
