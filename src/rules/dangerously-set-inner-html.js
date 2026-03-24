/**
 * Rule: dangerously-set-inner-html
 * Detects React dangerouslySetInnerHTML with user-controlled content.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const REACT_FILES = /\.(jsx|tsx)$/i;

/** @type {Rule} */
export const dangerouslySetInnerHtml = {
  id: 'dangerously-set-inner-html',
  name: 'dangerouslySetInnerHTML Usage',
  severity: 'critical',
  description: 'Detects React dangerouslySetInnerHTML with potentially user-controlled content.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!REACT_FILES.test(file.relativePath)) return [];

    const findings = [];
    const pattern = /dangerouslySetInnerHTML/g;
    pattern.lastIndex = 0;

    let match;
    while ((match = pattern.exec(file.content)) !== null) {
      const lineNum = file.content.slice(0, match.index).split('\n').length;
      const line = file.lines[lineNum - 1]?.trim();

      // Check if it's using sanitized content
      const context = file.content.slice(match.index, match.index + 200);
      const isSanitized = /(?:DOMPurify|sanitize|purify|xss|sanitizeHtml|dompurify)\s*[.(]/i.test(context);
      if (isSanitized) continue;

      findings.push({
        ruleId: 'dangerously-set-inner-html',
        ruleName: 'dangerouslySetInnerHTML Usage',
        severity: 'critical',
        message: 'dangerouslySetInnerHTML used without sanitization — XSS vulnerability.',
        file: file.relativePath,
        line: lineNum,
        evidence: line?.slice(0, 120),
        fix: 'Sanitize HTML before rendering with DOMPurify.sanitize(content). Install: npm install dompurify. Pass the sanitized result to __html. Or better yet, remove dangerouslySetInnerHTML entirely and use React\'s built-in XSS protection.',
      });
    }

    return findings;
  },
};
