/**
 * Rule: auth-token-no-expiry
 * Detects JWT/auth tokens issued without an expiration time.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

const JWT_SIGN = /jwt\.sign\s*\(/g;

/** @type {Rule} */
export const authTokenNoExpiry = {
  id: 'auth-token-no-expiry',
  name: 'Auth Token No Expiry',
  severity: 'warning',
  description: 'Detects JWT/auth tokens issued without an expiration time.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/jwt\.sign/i.test(file.content)) return [];

    const findings = [];

    JWT_SIGN.lastIndex = 0;
    let match;
    while ((match = JWT_SIGN.exec(file.content)) !== null) {
      // Look at the next ~300 chars for expiresIn or exp
      const afterSign = file.content.slice(match.index, match.index + 400);
      const hasExpiry = /expiresIn|expires_in|exp\s*:/i.test(afterSign);
      if (hasExpiry) continue;

      const lineNum = file.content.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: 'auth-token-no-expiry',
        ruleName: 'Auth Token No Expiry',
        severity: 'warning',
        message: 'JWT issued without expiration — token is valid forever if compromised.',
        file: file.relativePath,
        line: lineNum,
        evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
        fix: 'Add expiry to jwt.sign: jwt.sign(payload, secret, { expiresIn: "1h" }). Use short-lived access tokens (15min-1h) with refresh tokens for longer sessions.',
      });
    }

    return findings;
  },
};
