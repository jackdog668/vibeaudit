/**
 * Rule: session-fixation
 * Detects login handlers that don't regenerate the session after authentication.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const AUTH_FILES = /(?:auth|login|signin|sign-in|session|passport)/i;

/** @type {Rule} */
export const sessionFixation = {
  id: 'session-fixation',
  name: 'Session Fixation',
  severity: 'critical',
  description: 'Detects login handlers that do not regenerate the session ID after authentication.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!AUTH_FILES.test(file.relativePath) && !AUTH_FILES.test(file.content)) return [];

    // Does the file handle login?
    const hasLogin = /(?:login|signIn|sign_in|authenticate)\s*(?:=|:|\()/i.test(file.content);
    const hasSessionAssign = /(?:req\.session\.\w+\s*=|session\.\w+\s*=)/i.test(file.content);
    if (!hasLogin || !hasSessionAssign) return [];

    // Check for session regeneration
    const hasRegenerate = /(?:regenerate|destroy|rotateSession|req\.session\.regenerate|session\.regenerate|req\.session\.destroy)/i.test(file.content);
    if (hasRegenerate) return [];

    const lineIdx = file.lines.findIndex((l) => /(?:req\.session\.\w+\s*=|session\.\w+\s*=)/.test(l));

    return [{
      ruleId: 'session-fixation',
      ruleName: 'Session Fixation',
      severity: 'critical',
      message: 'Session data set after login without regenerating the session ID.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Regenerate the session after login: req.session.regenerate((err) => { req.session.userId = user.id; req.session.save(); }). This prevents session fixation attacks.',
    }];
  },
};
