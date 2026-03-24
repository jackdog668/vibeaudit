/**
 * Rule: nextjs-server-action-exposure
 * Detects Next.js server actions that lack authentication checks.
 * Server actions marked with "use server" are callable from the client
 * and must validate the caller's identity.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, findFunctions, containsCall, containsNode, getLine, isParseable } from '../ast.js';

const USE_SERVER = /['"]use server['"]/;
const SERVER_ACTION_FILE = /(?:actions|server-actions?)\.(js|ts|jsx|tsx)$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

function hasAuthCheckAST(body) {
  if (containsCall(body, /^(?:getServerSession|getSession|auth|getAuth|requireAuth|isAuthenticated|authenticate|withAuth|currentUser|getUser|verifyToken|getToken|clerkClient)$/i)) return true;
  if (containsNode(body, (node) => {
    if (node.type !== 'MemberExpression') return false;
    const prop = node.property;
    if (prop.type !== 'Identifier') return false;
    return /^(?:user|auth|userId)$/.test(prop.name);
  })) return true;
  return false;
}

/** @type {Rule} */
export const nextjsServerActionExposure = {
  id: 'nextjs-server-action-exposure',
  name: 'Next.js Server Action Exposure',
  severity: 'critical',
  description: 'Detects Next.js server actions without authentication checks.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    const hasDirective = USE_SERVER.test(file.content);
    const isActionFile = SERVER_ACTION_FILE.test(file.relativePath);
    if (!hasDirective && !isActionFile) return [];
    if (!isParseable(file.relativePath)) return [];

    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];
    const fns = findFunctions(ast);

    for (const fn of fns) {
      if (!fn.name) continue;
      // Only check exported async functions (server actions pattern)
      if (hasAuthCheckAST(fn.body || fn.node.body || fn.node)) continue;

      findings.push({
        ruleId: 'nextjs-server-action-exposure',
        ruleName: 'Next.js Server Action Exposure',
        severity: 'critical',
        message: `Server action "${fn.name}" has no authentication check. Anyone can call it.`,
        file: file.relativePath,
        line: fn.loc?.start?.line || getLine(fn.node) || 1,
        evidence: file.lines[(fn.loc?.start?.line || getLine(fn.node) || 1) - 1]?.trim().slice(0, 120),
        fix: 'Add auth at the top of every server action: "const session = await getServerSession(); if (!session) throw new Error(\'Unauthorized\');".',
      });
    }

    // Regex fallback — file-level check
    if (findings.length === 0 && hasDirective) {
      const hasAnyAuth = /(?:getServerSession|getSession|auth\(\)|requireAuth|currentUser|getUser|session\.user)/i.test(file.content);
      if (!hasAnyAuth) {
        const lineIdx = file.lines.findIndex((l) => USE_SERVER.test(l));
        findings.push({
          ruleId: 'nextjs-server-action-exposure',
          ruleName: 'Next.js Server Action Exposure',
          severity: 'critical',
          message: 'File uses "use server" directive but contains no authentication checks.',
          file: file.relativePath,
          line: lineIdx + 1,
          fix: 'Add authentication checks to every exported function in this server action file.',
        });
      }
    }

    return findings;
  },
};
