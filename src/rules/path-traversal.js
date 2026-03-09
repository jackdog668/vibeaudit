/**
 * Rule: path-traversal (AST-enhanced)
 * Detects file system operations using user input without sanitization.
 *
 * AST upgrade: Traces data flow — checks if user input (req.query, params)
 * flows into fs.readFile/writeFile/sendFile within the same function,
 * AND whether path.basename() or startsWith validation is applied first.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, findFunctions, containsNode, containsCall, getLine, isParseable } from '../ast.js';

/** Does this node reference user input (req.query.x, params.x, searchParams.get)? */
function isUserInput(node) {
  if (node.type !== 'MemberExpression') return false;
  const obj = node.object;
  if (obj?.type === 'Identifier' && /^(?:params|query|searchParams)$/.test(obj.name)) return true;
  if (obj?.type === 'MemberExpression' && obj.property?.type === 'Identifier' &&
      /^(?:params|query|body)$/.test(obj.property.name)) return true;
  return false;
}

/** Does this function use user input in file system operations? */
function hasUnsafeFileOp(funcBody) {
  const findings = [];

  // Check for path sanitization
  const hasSanitization = containsCall(funcBody, /^(?:basename|normalize)$/i) ||
    containsNode(funcBody, (n) => {
      if (n.type !== 'CallExpression') return false;
      const c = n.callee;
      return c?.type === 'MemberExpression' && c.object?.name === 'path' &&
             c.property?.type === 'Identifier' && /^(?:basename|normalize)$/.test(c.property.name);
    }) ||
    containsNode(funcBody, (n) => {
      // .startsWith(SAFE_DIR) check
      if (n.type !== 'CallExpression') return false;
      const c = n.callee;
      return c?.type === 'MemberExpression' && c.property?.name === 'startsWith';
    });

  if (hasSanitization) return [];

  // Look for fs operations with template literals or concatenation containing user input
  containsNode(funcBody, (node) => {
    if (node.type !== 'CallExpression') return false;
    const callee = node.callee;
    let methodName = '';

    if (callee?.type === 'Identifier') methodName = callee.name;
    else if (callee?.type === 'MemberExpression' && callee.property?.type === 'Identifier') {
      methodName = callee.property.name;
    }

    if (!/^(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|download|access|accessSync|stat|statSync|unlink|unlinkSync)$/.test(methodName)) return false;

    // Check if any argument tree contains user input
    for (const arg of node.arguments) {
      const hasInput = containsNode(arg, (n) => isUserInput(n));
      if (hasInput) { findings.push(node); return false; }
    }
    return false;
  });

  return findings;
}

// Regex fallback
const FS_REGEX = [
  { regex: /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(\s*(?:[`'"].*\$\{|.*\+\s*(?:req\.|request\.|params\.|query\.|body\.|file|name|path))/gi, label: 'File system op with user-controlled path' },
  { regex: /(?:res\.sendFile|res\.download)\s*\(\s*(?:[`'"].*\$\{|.*\+\s*(?:req\.|request\.|params\.|query\.))/gi, label: 'res.sendFile with user-controlled path' },
  { regex: /(?:readFile|createReadStream|sendFile)\s*\([^)]*(?:params\.\w+|query\.\w+|searchParams\.get)/gi, label: 'File served based on URL parameter' },
];
const SANITIZE_REGEX = [/path\.basename\s*\(/i, /\.replace\s*\([^)]*\.\./i, /\.startsWith\s*\(\s*(?:allowed|safe|base|upload|public)/i];

const SERVER_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/|controllers\/|middleware)/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const pathTraversal = {
  id: 'path-traversal',
  name: 'Path Traversal',
  severity: 'critical',
  description: 'Detects file system operations using user input without path sanitization.',

  check(file) {
    if (!SERVER_FILES.test(file.relativePath)) return [];
    if (SKIP.test(file.relativePath)) return [];

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const findings = [];
        for (const func of findFunctions(ast)) {
          for (const node of hasUnsafeFileOp(func.body)) {
            const line = getLine(node);
            findings.push({ ruleId: 'path-traversal', ruleName: 'Path Traversal', severity: 'critical',
              message: `Function "${func.name}" uses user input in a file system operation without path sanitization.`,
              file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: 'Use path.basename() to strip directory components, then verify: "if (!resolved.startsWith(ALLOWED_DIR)) return 403".' });
          }
        }
        return findings;
      }
    }

    // Regex fallback
    if (SANITIZE_REGEX.some((p) => p.test(file.content))) return [];
    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (line.trim().startsWith('//')) continue;
      for (const { regex, label } of FS_REGEX) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ ruleId: 'path-traversal', ruleName: 'Path Traversal', severity: 'critical',
            message: label, file: file.relativePath, line: i + 1,
            evidence: line.trim().slice(0, 120), fix: 'Use path.basename() and verify resolved path starts with your allowed directory.' });
        }
      }
    }
    return findings;
  },
};
