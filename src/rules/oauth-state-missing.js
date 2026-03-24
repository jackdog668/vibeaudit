/**
 * Rule: oauth-state-missing
 * Detects OAuth flows that don't use a state parameter for CSRF protection.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const OAUTH_URL_PATTERNS = [
  /(?:accounts\.google\.com|github\.com|facebook\.com|login\.microsoftonline).*(?:\/authorize|\/oauth)/gi,
  /(?:authorization_endpoint|authorize_url|authorizationUrl|auth_url)/gi,
  /\/oauth\/authorize/gi,
  /response_type=code/gi,
];

/** @type {Rule} */
export const oauthStateMissing = {
  id: 'oauth-state-missing',
  name: 'OAuth State Parameter Missing',
  severity: 'critical',
  description: 'Detects OAuth authorization flows without a state parameter for CSRF protection.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    let hasOAuth = false;
    for (const p of OAUTH_URL_PATTERNS) {
      p.lastIndex = 0;
      if (p.test(file.content)) { hasOAuth = true; break; }
    }
    if (!hasOAuth) return [];

    // Check if state parameter is used
    const hasState = /[&?]state=|state\s*[:=]/i.test(file.content);
    // Libraries that handle state automatically
    const hasOAuthLib = /(?:next-auth|NextAuth|passport|@auth\/|authjs|lucia|arctic|oslo)/i.test(file.content);
    if (hasState || hasOAuthLib) return [];

    const lineIdx = file.lines.findIndex((l) =>
      /(?:authorize|oauth|response_type)/i.test(l)
    );

    return [{
      ruleId: 'oauth-state-missing',
      ruleName: 'OAuth State Parameter Missing',
      severity: 'critical',
      message: 'OAuth flow has no state parameter — vulnerable to CSRF (login CSRF / account takeover).',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Generate a random state parameter, store in session, add to OAuth URL, and verify it in the callback: const state = crypto.randomUUID(); session.oauthState = state; // add &state=... to URL.',
    }];
  },
};
