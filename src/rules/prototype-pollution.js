/**
 * Rule: prototype-pollution
 * Detects deep merge/assign operations with user-controlled input.
 *
 * The attack: Send {"__proto__": {"isAdmin": true}} in a request body.
 * If the server does _.merge(config, req.body), now EVERY object in
 * the app has isAdmin = true. Instant privilege escalation.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Dangerous merge/assign patterns with user input. */
const POLLUTION_PATTERNS = [
  // lodash merge/defaultsDeep with user input
  {
    regex: /(?:_\.merge|_\.defaultsDeep|_\.mergeWith|lodash\.merge|lodash\.defaultsDeep)\s*\([^,]+,\s*(?:req\.body|body|request\.body|data|input|payload|params)/gi,
    label: 'lodash deep merge with user input — prototype pollution risk',
  },
  // Custom recursive merge (common in AI-generated code)
  {
    regex: /function\s+(?:deepMerge|merge|extend|deepExtend|deepAssign)\b/gi,
    label: 'Custom deep merge function — verify it guards against __proto__ and constructor.prototype',
    severity: 'warning',
  },
  // Object.assign with nested user data (less dangerous but still risky)
  {
    regex: /Object\.assign\s*\(\s*\w+,\s*(?:req\.body|body|request\.body)\s*\)/gi,
    label: 'Object.assign with full request body — consider destructuring specific fields instead',
    severity: 'warning',
  },
  // JSON.parse without sanitization in merge context
  {
    regex: /(?:merge|assign|extend|defaults)\s*\([^)]*JSON\.parse\s*\(\s*(?:req\.body|body|data|input)/gi,
    label: 'Parsed JSON merged into object — prototype pollution risk if __proto__ is in the payload',
  },
  // Direct __proto__ access (sometimes AI generates this)
  {
    regex: /\.__proto__\b/g,
    label: 'Direct __proto__ access — potential prototype pollution vector',
    severity: 'warning',
  },
];

/** Protection indicators. */
const PROTECTION_INDICATORS = [
  /(?:__proto__|constructor|prototype)\s*.*(?:delete|filter|reject|strip|remove|sanitize|ban|block)/i,
  /(?:Object\.freeze|Object\.seal)\s*\(\s*Object\.prototype/i,
  /(?:flatted|destr|safe-merge|secure-merge)/i,
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const prototypePollution = {
  id: 'prototype-pollution',
  name: 'Prototype Pollution',
  severity: 'critical',
  description: 'Detects deep merge/assign with user input — attackers can inject __proto__ to modify all objects in the app.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const hasProtection = PROTECTION_INDICATORS.some((p) => p.test(file.content));
    if (hasProtection) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, severity } of POLLUTION_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'prototype-pollution',
            ruleName: 'Prototype Pollution',
            severity: severity || 'critical',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Don't deep-merge raw user input into objects. Either: (1) Destructure only expected fields. (2) Use a safe merge library that blocks __proto__ and constructor.prototype. (3) Freeze Object.prototype. (4) Use schema validation (Zod/Yup) to strip unexpected keys. An attacker sending {"__proto__":{"isAdmin":true}} can modify every object in your app.`,
          });
        }
      }
    }

    return findings;
  },
};
