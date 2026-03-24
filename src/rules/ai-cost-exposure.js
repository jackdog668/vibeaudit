/**
 * Rule: ai-cost-exposure
 * Detects AI API calls with no token/cost limits — a bot could rack up
 * massive bills by spamming your endpoint.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const API_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/)/i;

const AI_CALLS = [
  /(?:openai|client)\.chat\.completions\.create\s*\(\s*\{/g,
  /anthropic\.messages\.create\s*\(\s*\{/g,
  /\.completions\.create\s*\(\s*\{/g,
];

/** @type {Rule} */
export const aiCostExposure = {
  id: 'ai-cost-exposure',
  name: 'AI Cost Exposure',
  severity: 'warning',
  description: 'Detects AI API calls without token limits in API routes.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!API_FILES.test(file.relativePath)) return [];

    const findings = [];

    for (const pattern of AI_CALLS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        // Look for the options object after the match — check for max_tokens
        const afterMatch = file.content.slice(match.index, match.index + 500);
        const hasMaxTokens = /max_tokens|maxTokens|max_completion_tokens/i.test(afterMatch);

        if (!hasMaxTokens) {
          const lineNum = file.content.slice(0, match.index).split('\n').length;
          findings.push({
            ruleId: 'ai-cost-exposure',
            ruleName: 'AI Cost Exposure',
            severity: 'warning',
            message: 'AI API call has no max_tokens limit — uncapped cost per request.',
            file: file.relativePath,
            line: lineNum,
            evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
            fix: 'Add max_tokens (e.g., max_tokens: 1000) to limit cost per request. Also add rate limiting to the API route and set spend alerts on your AI provider dashboard.',
          });
        }
      }
    }

    return findings;
  },
};
