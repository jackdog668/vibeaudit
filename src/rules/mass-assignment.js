/**
 * Rule: mass-assignment (AST-enhanced)
 * Detects code that passes the full request body to database operations.
 *
 * AST upgrade: Traces data flow per-function. Checks if req.body/body
 * is destructured or validated before being used in a DB call.
 * The old regex version passed if Zod was imported ANYWHERE — now it
 * checks if validation happens in the same function as the DB operation.
 */

/** @typedef {import('./types.js').Rule} Rule */

import {
  parseSource, findFunctions, containsNode, containsCall,
  getLine, isParseable
} from '../ast.js';

/** Check if a node is req.body, body, or request.body */
function isRequestBody(node) {
  if (node.type === 'Identifier' && node.name === 'body') return true;
  if (node.type === 'MemberExpression') {
    const obj = node.object;
    const prop = node.property;
    if (prop.type === 'Identifier' && prop.name === 'body') {
      if (obj.type === 'Identifier' && /^(?:req|request)$/.test(obj.name)) return true;
    }
  }
  return false;
}

/** Check if req.body flows directly into a DB operation or dangerous assignment */
function bodyInDbCall(funcBody) {
  const findings = [];

  containsNode(funcBody, (node) => {
    // Pattern 1: Object.assign(target, req.body)
    if (node.type === 'CallExpression' &&
        node.callee?.type === 'MemberExpression' &&
        node.callee.object?.name === 'Object' &&
        node.callee.property?.name === 'assign') {
      for (const arg of node.arguments.slice(1)) {
        if (isRequestBody(arg)) { findings.push(node); return false; }
      }
    }

    // Pattern 2: DB method call with body
    if (node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (callee?.type !== 'MemberExpression') return false;
    const method = callee.property;
    if (method?.type !== 'Identifier') return false;
    if (!/^(?:create|set|add|insert|insertMany|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate)$/.test(method.name)) return false;

    const callObj = callee.object;
    const looksLikeDb = containsNode(callObj, (n) => {
      if (n.type === 'Identifier') return /^(?:prisma|db|knex|mongoose|supabase|docRef|collectionRef|Model)$/i.test(n.name);
      if (n.type === 'MemberExpression' && n.property?.type === 'Identifier') {
        return /^(?:collection|doc|from|table|model)$/i.test(n.property.name);
      }
      return false;
    });
    if (!looksLikeDb) return false;

    // Check if any argument tree contains raw req.body (handles nesting)
    for (const arg of node.arguments) {
      const hasRawBody = containsNode(arg, (n) => {
        // Direct: create(body) or create(req.body)
        if (isRequestBody(n)) return true;
        // Spread: { ...req.body } or { ...body }
        if (n.type === 'SpreadElement' && isRequestBody(n.argument)) return true;
        return false;
      });
      if (hasRawBody) { findings.push(node); return false; }
    }
    return false;
  });

  return findings;
}

/** Check if destructuring or validation happens before DB call */
function hasBodyValidation(funcBody) {
  // Destructuring: const { name, email } = body / req.body / await request.json()
  const hasDestructuring = containsNode(funcBody, (node) => {
    if (node.type !== 'VariableDeclarator') return false;
    if (node.id?.type !== 'ObjectPattern') return false;
    // Value is body, req.body, or await req.json()
    const val = node.init;
    if (!val) return false;
    if (isRequestBody(val)) return true;
    // await request.json()
    if (val.type === 'AwaitExpression' && val.argument?.type === 'CallExpression') {
      const callee = val.argument.callee;
      if (callee?.type === 'MemberExpression' && callee.property?.name === 'json') return true;
    }
    return false;
  });

  if (hasDestructuring) return true;

  // Schema validation: .parse(body), .validate(body), .safeParse(body)
  return containsCall(funcBody, /^(?:parse|validate|safeParse|validateSync)$/i);
}

// Regex fallback
const MASS_REGEX = [
  { regex: /data\s*:\s*(?:req\.body|body|request\.body)\b/gi, label: 'Full request body passed to database' },
  { regex: /\.(?:create|insertMany|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate)\s*\(\s*(?:req\.body|body|request\.body)\b/gi, label: 'Full request body in DB operation' },
  { regex: /\.(?:set|update|add)\s*\(\s*(?:req\.body|body|request\.body)\b/gi, label: 'Full request body passed to Firestore' },
  { regex: /(?:data|set|update|create|insert)\s*[:=]\s*\{[^}]*\.\.\.(?:req\.body|body|request\.body)/gi, label: 'Request body spread into DB operation' },
  { regex: /Object\.assign\s*\([^,]+,\s*(?:req\.body|body|request\.body)\b/gi, label: 'Object.assign with request body' },
];
const WHITELIST_REGEX = [
  /const\s*\{[^}]+\}\s*=\s*(?:req\.body|body|request\.body|await\s+request\.json)/i,
  /(?:\.parse|\.validate|\.safeParse|\.validateSync)\s*\(\s*(?:req\.body|body|request\.body)/i,
  /(?:pick|omit|allowedFields|sanitize)\s*\(/i,
  /(?:zod|yup|joi|superstruct|valibot|ajv|typebox)/i,
];

const SERVER_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/|controllers\/)/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const massAssignment = {
  id: 'mass-assignment',
  name: 'Mass Assignment',
  severity: 'critical',
  description: 'Detects code that passes the full request body to database operations — attackers can inject fields like role or isAdmin.',

  check(file) {
    if (!SERVER_FILES.test(file.relativePath)) return [];
    if (SKIP.test(file.relativePath)) return [];

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const findings = [];
        const functions = findFunctions(ast);

        for (const func of functions) {
          // Does this function have validation BEFORE the DB call?
          if (hasBodyValidation(func.body)) continue;

          const dbCalls = bodyInDbCall(func.body);
          for (const callNode of dbCalls) {
            const line = getLine(callNode);
            findings.push({
              ruleId: 'mass-assignment',
              ruleName: 'Mass Assignment',
              severity: 'critical',
              message: `Function "${func.name}" passes raw request body to a database operation without destructuring or schema validation first.`,
              file: file.relativePath,
              line,
              evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: `Destructure only expected fields: "const { name, email } = req.body" then pass those explicitly. Or validate with Zod: "schema.parse(req.body)".`,
            });
          }
        }
        return findings;
      }
    }

    // Regex fallback
    if (WHITELIST_REGEX.some((p) => p.test(file.content))) return [];
    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (line.trim().startsWith('//')) continue;
      for (const { regex, label } of MASS_REGEX) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ ruleId: 'mass-assignment', ruleName: 'Mass Assignment', severity: 'critical',
            message: label, file: file.relativePath, line: i + 1,
            evidence: line.trim().slice(0, 120),
            fix: 'Destructure only expected fields or use schema validation (Zod/Yup).' });
        }
      }
    }
    return findings;
  },
};
