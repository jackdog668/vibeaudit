/**
 * Rule: unsafe-file-upload (AST-enhanced)
 * Detects file upload handlers missing type validation, size limits.
 *
 * AST upgrade: Per-function analysis. Checks if the function that
 * handles file upload also validates type/size within its scope.
 * Old version passed if sharp was imported anywhere in the file.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, findFunctions, containsNode, containsCall, getLine, isParseable } from '../ast.js';

/** Does this function handle file uploads? */
function handlesUpload(funcBody) {
  return containsNode(funcBody, (n) => {
    if (n.type !== 'CallExpression') return false;
    const callee = n.callee;
    // formData.get("file") / formData.get("image") — NOT searchParams.get
    if (callee?.type === 'MemberExpression' && callee.property?.name === 'get' &&
        callee.object?.type === 'Identifier' && /^(?:formData|form|fileData)$/i.test(callee.object.name)) {
      const firstArg = n.arguments?.[0];
      if (firstArg?.type === 'Literal' && /^(?:file|image|upload|attachment|document|avatar|photo|video|media)/i.test(firstArg.value)) return true;
    }
    // multer() / upload.single() / upload.array()
    if (callee?.type === 'Identifier' && /^(?:multer|formidable|busboy)$/i.test(callee.name)) return true;
    if (callee?.type === 'MemberExpression' && callee.property?.type === 'Identifier' &&
        /^(?:single|array|fields)$/.test(callee.property.name)) return true;
    return false;
  }) ||
  containsNode(funcBody, (n) => n.type === 'MemberExpression' &&
    n.object?.type === 'Identifier' && n.object.name === 'req' &&
    n.property?.type === 'Identifier' && /^(?:file|files)$/.test(n.property.name));
}

/** Does this function validate uploaded files? */
function hasFileValidation(funcBody) {
  // Type check: .type ===, .mimetype, allowedTypes.includes, fileFilter
  const hasTypeCheck = containsNode(funcBody, (n) => {
    if (n.type === 'MemberExpression' && n.property?.type === 'Identifier' &&
        /^(?:type|mimetype|mimeType|contentType)$/.test(n.property.name)) return true;
    if (n.type === 'Identifier' && /^(?:allowedTypes|allowedExtensions|ALLOWED_TYPES|fileFilter)$/i.test(n.name)) return true;
    return false;
  });

  // Size check: .size, maxSize, limits
  const hasSizeCheck = containsNode(funcBody, (n) => {
    if (n.type === 'MemberExpression' && n.property?.type === 'Identifier' &&
        /^(?:size|fileSize|maxSize)$/.test(n.property.name)) return true;
    if (n.type === 'Identifier' && /^(?:MAX_SIZE|maxSize|sizeLimit|MAX_FILE_SIZE)$/i.test(n.name)) return true;
    if (n.type === 'Property' && n.key?.type === 'Identifier' && /^(?:limits|fileSize|fieldSize)$/.test(n.key.name)) return true;
    return false;
  });

  // Processing check: sharp, jimp
  const hasProcessing = containsCall(funcBody, /^(?:sharp|jimp|resize|toBuffer)$/i);

  return (hasTypeCheck || hasProcessing) && (hasSizeCheck || hasProcessing);
}

// Regex fallback
const UPLOAD_REGEX = [
  { regex: /multer\s*\(/gi, label: 'multer' },
  { regex: /formidable\s*\(/gi, label: 'formidable' },
  { regex: /formData\.get\s*\(\s*['"`](?:file|image|upload|attachment|document|avatar|photo)/gi, label: 'FormData file' },
  { regex: /req\.files?\b/g, label: 'req.file(s)' },
  { regex: /(?:uploadBytes|uploadBytesResumable|upload\.single|upload\.array)\s*\(/gi, label: 'cloud upload' },
];
const VALID_REGEX = [
  /(?:mimetype|mime_type|mimeType|contentType|content_type|type)\s*(?:===|!==|==|!=|\.includes)/i,
  /(?:extname|extension|allowedTypes|allowedExtensions|ALLOWED_TYPES)/i,
  /(?:size|fileSize|maxSize|MAX_SIZE|sizeLimit|limits?\s*:\s*\{[^}]*(?:fileSize|fieldSize))/i,
  /(?:sharp|jimp|imageSize)/i,
  /fileFilter/i,
];

const SERVER_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/|middleware|upload)/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const unsafeFileUpload = {
  id: 'unsafe-file-upload',
  name: 'Unsafe File Upload',
  severity: 'critical',
  description: 'Detects file upload handlers missing type validation, size limits, or content verification.',

  check(file) {
    if (!SERVER_FILES.test(file.relativePath)) return [];
    if (SKIP.test(file.relativePath)) return [];

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const findings = [];
        for (const func of findFunctions(ast)) {
          if (!handlesUpload(func.body)) continue;
          if (hasFileValidation(func.body)) continue;

          const line = func.loc?.start?.line || 1;
          findings.push({ ruleId: 'unsafe-file-upload', ruleName: 'Unsafe File Upload', severity: 'critical',
            message: `Function "${func.name}" handles file uploads without type/size validation in scope.`,
            file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
            fix: 'Validate MIME type against an allowlist and set a max file size. The HTML accept="" attribute is NOT security.' });
        }
        return findings;
      }
    }

    // Regex fallback
    let hasUpload = false, uploadLine = 0, uploadLib = '';
    for (let i = 0; i < file.lines.length; i++) {
      if (file.lines[i].trim().startsWith('//')) continue;
      for (const { regex, label } of UPLOAD_REGEX) {
        regex.lastIndex = 0;
        if (regex.test(file.lines[i])) { hasUpload = true; uploadLine = i + 1; uploadLib = label; break; }
      }
      if (hasUpload) break;
    }
    if (!hasUpload) return [];
    const hasType = VALID_REGEX.slice(0, 2).some((p) => p.test(file.content));
    const hasSize = VALID_REGEX.slice(2, 3).some((p) => p.test(file.content));
    const hasProc = VALID_REGEX.slice(3).some((p) => p.test(file.content));
    if ((hasType || hasProc) && (hasSize || hasProc)) return [];
    const missing = [];
    if (!hasType && !hasProc) missing.push('file type/MIME validation');
    if (!hasSize && !hasProc) missing.push('file size limits');
    return [{ ruleId: 'unsafe-file-upload', ruleName: 'Unsafe File Upload', severity: 'critical',
      message: `File upload handler (${uploadLib}) is missing: ${missing.join(', ')}.`,
      file: file.relativePath, line: uploadLine,
      evidence: file.lines[uploadLine - 1]?.trim().slice(0, 120),
      fix: 'Validate MIME type against allowlist and set max file size.' }];
  },
};
