/**
 * Rule: insecure-error-handling
 * Detects error handling that leaks internal info to users.
 * AI-generated code loves to send full error objects to the client.
 */

/** @typedef {import('./types.js').Rule} Rule */

const LEAK_PATTERNS = [
  // Sending raw error to response
  {
    regex: /res\.\w*(?:json|send|status)\s*\([^)]*(?:err(?:or)?\.(?:message|stack|toString)|error\))/gi,
    label: 'Raw error details sent in HTTP response',
  },
  // Next.js returning error in response
  {
    regex: /(?:NextResponse|Response)\.json\s*\([^)]*(?:err(?:or)?\.(?:message|stack)|error\.)/gi,
    label: 'Error details returned in API response',
  },
  // console.log of error in server code (not fatal, but sloppy)
  {
    regex: /console\.(?:log|info)\s*\(\s*(?:['"`].*(?:error|err|failed|exception).*['"`]\s*,\s*)?err(?:or)?\s*\)/gi,
    label: 'Error logged with console.log instead of console.error',
    severity: 'info',
  },
  // Catch block that does nothing
  {
    regex: /catch\s*\([^)]*\)\s*\{\s*\}/g,
    label: 'Empty catch block — errors silently swallowed',
    severity: 'warning',
  },
  // Stack trace in response
  {
    regex: /(?:err(?:or)?\.stack|Error\.captureStackTrace)/g,
    label: 'Stack trace potentially exposed',
  },
];

/** Only flag these in server-side files. */
const SERVER_FILE_PATTERNS = /(?:api\/|routes\/|server\/|functions\/|middleware|\.server\.|pages\/api\/)/i;

/** @type {Rule} */
export const insecureErrorHandling = {
  id: 'insecure-error-handling',
  name: 'Insecure Error Handling',
  severity: 'warning',
  description: 'Detects error handling that exposes internal details, stack traces, or silently swallows errors.',

  check(file) {
    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, severity } of LEAK_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          const isServerFile = SERVER_FILE_PATTERNS.test(file.relativePath);
          // Only flag response-related patterns in server files.
          if (label.includes('response') && !isServerFile) continue;

          findings.push({
            ruleId: 'insecure-error-handling',
            ruleName: 'Insecure Error Handling',
            severity: severity || 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Return a generic error message to users ("Something went wrong"). Log full error details server-side only with console.error(). Never expose .stack or raw error objects in responses.`,
          });
        }
      }
    }

    return findings;
  },
};
