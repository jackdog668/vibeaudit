/**
 * Rule: ai-prompt-injection
 * Detects user input passed directly to LLM API calls without sanitization.
 * This allows attackers to manipulate AI behavior via crafted input.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, findFunctions, containsCall, containsNode, getLine, isParseable } from '../ast.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const AI_CALL_PATTERNS = [
  /openai\.(?:chat\.completions|completions)\.create/g,
  /anthropic\.messages\.create/g,
  /\.chat\.completions\.create/g,
  /generateText\s*\(/g,
  /streamText\s*\(/g,
  /\.generate\s*\(\s*\{/g,
];

const USER_INPUT_IN_PROMPT = [
  // Template literal with user input in content/prompt
  /(?:content|prompt|message|text)\s*:\s*`[^`]*\$\{(?:req\.|request\.|body\.|params\.|query\.|input|userInput|message|prompt|user)/g,
  // String concat with user input
  /(?:content|prompt|message|text)\s*:\s*['"][^'"]*['"]\s*\+\s*(?:req\.|request\.|body\.|params\.|query\.|input|userInput|message)/g,
  // Direct variable from request
  /(?:content|prompt)\s*:\s*(?:req\.body|req\.query|request\.body)\./g,
];

/** @type {Rule} */
export const aiPromptInjection = {
  id: 'ai-prompt-injection',
  name: 'AI Prompt Injection',
  severity: 'critical',
  description: 'Detects user input passed directly into LLM prompts without sanitization.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    // Quick check: does the file even use AI APIs?
    if (!/(?:openai|anthropic|generateText|streamText|completions|messages\.create)/i.test(file.content)) return [];

    const findings = [];

    // Check for user input concatenated into prompts
    for (const pattern of USER_INPUT_IN_PROMPT) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'ai-prompt-injection',
          ruleName: 'AI Prompt Injection',
          severity: 'critical',
          message: 'User input interpolated directly into LLM prompt — vulnerable to prompt injection.',
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Separate system prompts from user input. Use the "user" message role for user content, never embed user input in the "system" prompt. Add input validation and length limits.',
        });
      }
    }

    // AST check: look for req.body passed directly to AI API content field
    if (isParseable(file.relativePath) && findings.length === 0) {
      const ast = parseSource(file.content);
      if (ast) {
        const hasAICall = AI_CALL_PATTERNS.some((p) => { p.lastIndex = 0; return p.test(file.content); });
        if (hasAICall) {
          const fns = findFunctions(ast);
          for (const fn of fns) {
            const body = fn.body || fn.node?.body || fn.node;
            if (!body) continue;
            // Check if function uses both request input and AI calls
            const hasReqInput = containsNode(body, (n) =>
              n.type === 'MemberExpression' && n.object?.type === 'MemberExpression' &&
              n.object.object?.name === 'req' && n.object.property?.name === 'body'
            );
            const hasAI = containsCall(body, /^(?:create|generate|generateText|streamText)$/i);
            if (hasReqInput && hasAI) {
              findings.push({
                ruleId: 'ai-prompt-injection',
                ruleName: 'AI Prompt Injection',
                severity: 'critical',
                message: 'Request body data flows into an AI API call — potential prompt injection.',
                file: file.relativePath,
                line: fn.loc?.start?.line || getLine(fn.node) || 1,
                fix: 'Validate and sanitize user input before passing to AI. Separate system instructions from user content using message roles.',
              });
            }
          }
        }
      }
    }

    return findings;
  },
};
