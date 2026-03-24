/**
 * Rule: ai-response-trusted
 * Detects LLM/AI API responses used in dangerous sinks without sanitization.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const DANGEROUS_PATTERNS = [
  // AI response used in eval
  { pattern: /eval\s*\(\s*(?:response|result|completion|aiResponse|output|generated|content)/g, label: 'AI response passed to eval()' },
  // AI response used in innerHTML
  { pattern: /innerHTML\s*=\s*(?:response|result|completion|aiResponse|output|generated|content)/g, label: 'AI response set as innerHTML' },
  // AI response used in SQL
  { pattern: /(?:query|execute|exec)\s*\(\s*(?:`[^`]*\$\{(?:response|result|completion|aiResponse|output|generated)|['"][^'"]*['"]\s*\+\s*(?:response|result|completion|aiResponse|output|generated))/g, label: 'AI response in SQL query' },
  // AI response used in dangerouslySetInnerHTML
  { pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:response|result|completion|aiResponse|output|generated|content)/g, label: 'AI response in dangerouslySetInnerHTML' },
  // AI response used in Function constructor
  { pattern: /new\s+Function\s*\(\s*(?:response|result|completion|aiResponse|output|generated)/g, label: 'AI response in Function constructor' },
];

/** @type {Rule} */
export const aiResponseTrusted = {
  id: 'ai-response-trusted',
  name: 'AI Response Trusted',
  severity: 'warning',
  description: 'Detects LLM responses used in eval, innerHTML, or SQL without sanitization.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:openai|anthropic|generateText|streamText|completion|aiResponse)/i.test(file.content)) return [];

    const findings = [];

    for (const { pattern, label } of DANGEROUS_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'ai-response-trusted',
          ruleName: 'AI Response Trusted',
          severity: 'warning',
          message: `${label} — AI output can contain malicious content.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Never pass AI responses directly to eval, innerHTML, SQL, or other code execution sinks. Sanitize and validate AI output before use.',
        });
      }
    }

    return findings;
  },
};
