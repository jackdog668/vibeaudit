/**
 * Rule: race-condition
 * Detects TOCTOU (Time-of-check to time-of-use) bugs where a value is
 * checked then used without atomicity — e.g., checking balance then deducting.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const API_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/)/i;

const TOCTOU_PATTERNS = [
  // Check balance/stock then update
  { pattern: /(?:balance|stock|inventory|quantity|count|seats|tickets)\s*[<>=!]+[\s\S]{0,200}(?:update|decrement|subtract|reduce|\-=)/gi, label: 'Check-then-update on balance/inventory without lock' },
  // If exists then create (duplicate race)
  { pattern: /(?:findOne|findUnique|findFirst|find\()[\s\S]{0,300}(?:\.create\(|\.insert\(|\.save\()/gi, label: 'Find-then-create race condition (possible duplicate)' },
];

/** @type {Rule} */
export const raceCondition = {
  id: 'race-condition',
  name: 'Race Condition',
  severity: 'critical',
  description: 'Detects check-then-act patterns without atomicity (TOCTOU bugs).',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!API_FILES.test(file.relativePath)) return [];

    // Check for atomic alternatives already in use
    if (/\$inc|\$set.*\$where|transaction|FOR UPDATE|SERIALIZABLE|atomicUpdate|compareAndSwap/i.test(file.content)) return [];

    const findings = [];

    for (const { pattern, label } of TOCTOU_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        // Check context for transaction/lock
        const context = file.content.slice(Math.max(0, match.index - 200), match.index + match[0].length + 200);
        if (/transaction|\.lock\(|mutex|semaphore|FOR UPDATE/i.test(context)) continue;

        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'race-condition',
          ruleName: 'Race Condition',
          severity: 'critical',
          message: `${label} — concurrent requests can cause inconsistency.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Use database transactions or atomic operations. For Prisma: prisma.$transaction(). For MongoDB: $inc for counters. For SQL: SELECT ... FOR UPDATE within a transaction.',
        });
      }
    }

    return findings;
  },
};
