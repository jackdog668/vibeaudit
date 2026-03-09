/**
 * AST Utilities for Vibe Audit.
 *
 * Uses acorn for strict parsing, acorn-loose as fallback for
 * incomplete / AI-generated code that may not be syntactically perfect.
 *
 * Provides scope-aware traversal so rules can ask questions like:
 * "In this function, does X happen before Y?"
 * "Does this function that uses params.id also check session.user.id?"
 */

import * as acorn from 'acorn';
import * as acornLoose from 'acorn-loose';

/**
 * Parse JavaScript/TypeScript source into an AST.
 * Tries strict parsing first, falls back to loose parsing.
 * Returns null if parsing fails entirely.
 *
 * @param {string} source
 * @returns {import('acorn').Node | null}
 */
export function parseSource(source) {
  // Strip TypeScript-only syntax that acorn can't handle.
  const cleaned = stripTypeAnnotations(source);

  const opts = {
    ecmaVersion: 'latest',
    sourceType: 'module',
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    locations: true,
  };

  try {
    return acorn.parse(cleaned, opts);
  } catch {
    // Strict parse failed — try loose parser (tolerates errors).
    try {
      return acornLoose.parse(cleaned, opts);
    } catch {
      return null;
    }
  }
}

/**
 * Strip TypeScript type annotations so acorn can parse the file.
 * This is a best-effort transform — it handles the most common cases.
 *
 * @param {string} source
 * @returns {string}
 */
function stripTypeAnnotations(source) {
  return source
    // Remove type imports: import type { X } from 'y'
    .replace(/import\s+type\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];?/g, '')
    // Remove type-only exports: export type { X }
    .replace(/export\s+type\s+\{[^}]*\};?/g, '')
    // Remove interface declarations
    .replace(/(?:export\s+)?interface\s+\w+(?:\s+extends\s+[^{]+)?\s*\{[^}]*\}/g, '')
    // Remove type alias declarations
    .replace(/(?:export\s+)?type\s+\w+\s*=\s*[^;]+;/g, '')
    // Remove parameter type annotations: (param: Type)
    .replace(/:\s*(?:string|number|boolean|any|void|never|unknown|null|undefined|Record|Array|Promise|Response|Request|NextRequest)(?:<[^>]*>)?(?:\s*\[\s*\])?(?:\s*\|[^,)=]+)?/g, '')
    // Remove return type annotations: ): Type {
    .replace(/\)\s*:\s*\w+(?:<[^>]*>)?\s*(?:=>|\{)/g, ') $&'.slice(2))
    // Remove 'as Type' assertions
    .replace(/\s+as\s+\w+(?:<[^>]*>)?/g, '')
    // Remove angle bracket assertions: <Type>expr
    .replace(/<(?:string|number|boolean|any)>/g, '')
    // Remove non-null assertions: expr!
    .replace(/(\w)!\./g, '$1.')
    // Remove satisfies keyword
    .replace(/\s+satisfies\s+\w+/g, '');
}

/**
 * Simple AST walker. Visits every node in the tree.
 *
 * @param {import('acorn').Node} node
 * @param {(node: import('acorn').Node, ancestors: import('acorn').Node[]) => void} visitor
 * @param {import('acorn').Node[]} [ancestors]
 */
export function walk(node, visitor, ancestors = []) {
  if (!node || typeof node !== 'object') return;

  visitor(node, ancestors);

  const newAncestors = [...ancestors, node];

  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc') continue;
    const child = node[key];

    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) {
          walk(item, visitor, newAncestors);
        }
      }
    } else if (child && typeof child === 'object' && child.type) {
      walk(child, visitor, newAncestors);
    }
  }
}

/**
 * Find all function/method bodies in the AST.
 * Returns an array of { node, body, name, loc } for each function.
 *
 * @param {import('acorn').Node} ast
 * @returns {Array<{node: import('acorn').Node, body: import('acorn').Node, name: string, loc: object}>}
 */
export function findFunctions(ast) {
  const functions = [];

  walk(ast, (node) => {
    let name = '<anonymous>';
    let body = null;

    switch (node.type) {
      case 'FunctionDeclaration':
        name = node.id?.name || '<anonymous>';
        body = node.body;
        break;
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
        body = node.body;
        // Try to get name from parent assignment
        break;
      case 'MethodDefinition':
        name = node.key?.name || node.key?.value || '<method>';
        body = node.value?.body;
        break;
      default:
        return;
    }

    if (body) {
      functions.push({ node, body, name, loc: node.loc });
    }
  });

  return functions;
}

/**
 * Check if a subtree contains a node matching a predicate.
 *
 * @param {import('acorn').Node} root
 * @param {(node: import('acorn').Node) => boolean} predicate
 * @returns {boolean}
 */
export function containsNode(root, predicate) {
  let found = false;
  walk(root, (node) => {
    if (!found && predicate(node)) found = true;
  });
  return found;
}

/**
 * Find all nodes matching a predicate.
 *
 * @param {import('acorn').Node} root
 * @param {(node: import('acorn').Node) => boolean} predicate
 * @returns {import('acorn').Node[]}
 */
export function findNodes(root, predicate) {
  const results = [];
  walk(root, (node) => {
    if (predicate(node)) results.push(node);
  });
  return results;
}

/**
 * Check if a node is a member expression matching a dotted path.
 * e.g. isMemberPath(node, 'req', 'body') matches req.body
 * e.g. isMemberPath(node, 'params', 'id') matches params.id
 *
 * @param {import('acorn').Node} node
 * @param  {...string} path
 * @returns {boolean}
 */
export function isMemberPath(node, ...path) {
  if (path.length === 1) {
    return node.type === 'Identifier' && node.name === path[0];
  }

  if (node.type !== 'MemberExpression') return false;

  const last = path[path.length - 1];
  const propMatch =
    (node.property.type === 'Identifier' && node.property.name === last) ||
    (node.property.type === 'Literal' && node.property.value === last);

  if (!propMatch) return false;

  return isMemberPath(node.object, ...path.slice(0, -1));
}

/**
 * Check if any member expression in a subtree accesses a property
 * that matches a pattern (e.g., any property containing "id").
 *
 * @param {import('acorn').Node} root
 * @param {RegExp} propertyPattern
 * @returns {import('acorn').Node[]}
 */
export function findMemberAccess(root, propertyPattern) {
  return findNodes(root, (node) => {
    if (node.type !== 'MemberExpression') return false;
    const prop = node.property;
    if (prop.type === 'Identifier') return propertyPattern.test(prop.name);
    if (prop.type === 'Literal') return propertyPattern.test(String(prop.value));
    return false;
  });
}

/**
 * Check if a subtree contains a call to a function matching a name pattern.
 *
 * @param {import('acorn').Node} root
 * @param {RegExp} namePattern
 * @returns {boolean}
 */
export function containsCall(root, namePattern) {
  return containsNode(root, (node) => {
    if (node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (callee.type === 'Identifier') return namePattern.test(callee.name);
    if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
      return namePattern.test(callee.property.name);
    }
    return false;
  });
}

/**
 * Get the source line number for an AST node.
 *
 * @param {import('acorn').Node} node
 * @returns {number}
 */
export function getLine(node) {
  return node.loc?.start?.line || 0;
}

/**
 * Check if a file is parseable (JS/JSX/TS/TSX/MJS).
 *
 * @param {string} relativePath
 * @returns {boolean}
 */
export function isParseable(relativePath) {
  return /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(relativePath);
}
