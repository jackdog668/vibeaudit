/**
 * Rule: insecure-randomness (AST-enhanced)
 * Detects Math.random() used for security-sensitive values.
 *
 * AST upgrade: Traces what Math.random() feeds into. Only flags when
 * the result is assigned to a variable with a security-related name
 * (token, key, secret, code, session, etc.) — not random color picks.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, getLine, isParseable } from '../ast.js';

/** Security-sensitive variable name patterns */
const SENSITIVE_NAMES = /^(?:token|secret|key|code|nonce|salt|session|invite|reset|verify|confirm|otp|pin|id|uuid|guid|hash|seed|random(?:Id|Token|Key|Code|String|Bytes))/i;

/** Check if a node is or contains Math.random() */
function containsMathRandom(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'CallExpression' &&
      node.callee?.type === 'MemberExpression' &&
      node.callee.object?.name === 'Math' &&
      node.callee.property?.name === 'random') return true;
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) { for (const item of child) { if (item?.type && containsMathRandom(item)) return true; } }
    else if (child?.type && containsMathRandom(child)) return true;
  }
  return false;
}

// Regex fallback
const INSECURE_REGEX = [
  { regex: /(?:token|secret|key|code|nonce|salt|session|invite|reset|verify|confirm|otp|pin)\w*\s*=\s*[^;\n]*Math\.random/gi, label: 'Math.random() used for token/key generation — predictable' },
  { regex: /function\s+(?:generate|create|make|get)\w*(?:Token|Key|Code|Id|Secret|Nonce|Salt|Session|OTP|PIN)\s*\([^)]*\)\s*\{[^}]*Math\.random/gi, label: 'Token generation function uses Math.random()' },
];

const SKIP = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const insecureRandomness = {
  id: 'insecure-randomness',
  name: 'Insecure Randomness',
  severity: 'critical',
  description: 'Detects Math.random() used for tokens, keys, or session IDs — output is predictable.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!file.content.includes('Math.random')) return [];

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const findings = [];

        walk(ast, (node) => {
          // Variable assignment: const token = ...Math.random()...
          if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
            if (SENSITIVE_NAMES.test(node.id.name) && node.init && containsMathRandom(node.init)) {
              const line = getLine(node);
              findings.push({ ruleId: 'insecure-randomness', ruleName: 'Insecure Randomness', severity: 'critical',
                message: `"${node.id.name}" generated with Math.random() — predictable, not cryptographically secure.`,
                file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
                fix: 'Use crypto.randomBytes(32).toString("hex") or crypto.randomUUID() for security-sensitive values.' });
            }
          }

          // Return statement in a function with security-related name
          if (node.type === 'FunctionDeclaration' && node.id?.type === 'Identifier' &&
              SENSITIVE_NAMES.test(node.id.name) && containsMathRandom(node.body)) {
            const line = getLine(node);
            findings.push({ ruleId: 'insecure-randomness', ruleName: 'Insecure Randomness', severity: 'critical',
              message: `Function "${node.id.name}" uses Math.random() — output is predictable.`,
              file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: 'Use crypto.randomBytes() or crypto.randomUUID() instead of Math.random().' });
          }
        });

        return findings;
      }
    }

    // Regex fallback
    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (line.trim().startsWith('//')) continue;
      for (const { regex, label } of INSECURE_REGEX) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ ruleId: 'insecure-randomness', ruleName: 'Insecure Randomness', severity: 'critical',
            message: label, file: file.relativePath, line: i + 1,
            evidence: line.trim().slice(0, 120), fix: 'Use crypto.randomBytes() or crypto.randomUUID().' });
        }
      }
    }
    return findings;
  },
};
