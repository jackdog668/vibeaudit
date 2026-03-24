/**
 * Rule: eval-usage
 * Detects direct eval() or new Function() with dynamic input.
 * The existing no-input-validation rule catches eval with user input;
 * this rule catches ALL eval usage as a broader security concern.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, getLine, isParseable } from '../ast.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.d\.ts$)/i;
// Allow eval references in rule files that scan for eval
const SKIP_RULES = /src\/rules\//i;

/** @type {Rule} */
export const evalUsage = {
  id: 'eval-usage',
  name: 'Eval Usage',
  severity: 'critical',
  description: 'Detects eval() and new Function() usage with dynamic arguments.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];
    if (!isParseable(file.relativePath)) return [];

    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];

    walk(ast, (node) => {
      // eval(...)
      if (node.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'eval') {
        // Skip eval with only string literals (less dangerous, used in config)
        const arg = node.arguments?.[0];
        if (arg?.type === 'Literal' && typeof arg.value === 'string') return;

        const line = getLine(node) || 1;
        findings.push({
          ruleId: 'eval-usage',
          ruleName: 'Eval Usage',
          severity: 'critical',
          message: 'eval() with dynamic argument — arbitrary code execution.',
          file: file.relativePath,
          line,
          evidence: file.lines[line - 1]?.trim().slice(0, 120),
          fix: 'Remove eval(). Use JSON.parse() for data, a proper parser for expressions, or a sandboxed evaluator. eval() is almost never needed.',
        });
      }

      // new Function(...)
      if (node.type === 'NewExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'Function') {
        const arg = node.arguments?.[0];
        if (arg?.type === 'Literal') return;

        const line = getLine(node) || 1;
        findings.push({
          ruleId: 'eval-usage',
          ruleName: 'Eval Usage',
          severity: 'critical',
          message: 'new Function() with dynamic argument — equivalent to eval().',
          file: file.relativePath,
          line,
          evidence: file.lines[line - 1]?.trim().slice(0, 120),
          fix: 'Replace new Function() with a safe alternative. Use a proper parser or predefined function lookup.',
        });
      }
    });

    return findings;
  },
};
