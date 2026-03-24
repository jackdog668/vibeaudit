/**
 * Rule: password-reset-weak
 * Detects weak password reset token generation or missing expiry.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;
const RESET_FILES = /(?:reset|forgot|password|recover)/i;

/** @type {Rule} */
export const passwordResetWeak = {
  id: 'password-reset-weak',
  name: 'Weak Password Reset',
  severity: 'warning',
  description: 'Detects predictable password reset tokens or tokens without expiration.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!RESET_FILES.test(file.relativePath) && !RESET_FILES.test(file.content)) return [];

    const findings = [];

    // Check for Math.random used for reset tokens
    if (/(?:reset|token|code).*Math\.random/i.test(file.content) || /Math\.random.*(?:reset|token|code)/i.test(file.content)) {
      const lineIdx = file.lines.findIndex((l) => /Math\.random/.test(l));
      findings.push({
        ruleId: 'password-reset-weak',
        ruleName: 'Weak Password Reset',
        severity: 'warning',
        message: 'Password reset token generated with Math.random() — predictable.',
        file: file.relativePath,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        evidence: file.lines[lineIdx]?.trim().slice(0, 120),
        fix: 'Use crypto.randomBytes(32).toString("hex") for reset tokens. Never use Math.random() for security tokens.',
      });
    }

    // Check for reset token without expiry — only in files that handle the reset flow
    const hasResetHandler = /(?:forgotPassword|resetPassword|password.?reset|forgot.?password)\s*(?:=|:|\()|\/(?:reset|forgot)/i.test(file.content);
    const hasResetStorage = /(?:resetToken|reset_token)\s*[:=]|save.*(?:resetToken|reset_token)|\.update.*(?:resetToken|reset_token)/i.test(file.content);
    const hasExpiry = /(?:expir|ttl|validUntil|expiresAt|expires_at|Date\.now.*reset|resetExpiry|token.*expir)/i.test(file.content);
    if (hasResetHandler && hasResetStorage && !hasExpiry) {
      const lineIdx = file.lines.findIndex((l) => /(?:resetToken|reset_token|passwordReset)/i.test(l));
      findings.push({
        ruleId: 'password-reset-weak',
        ruleName: 'Weak Password Reset',
        severity: 'warning',
        message: 'Password reset token has no expiration — tokens stay valid forever.',
        file: file.relativePath,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        fix: 'Add an expiry to reset tokens (15-60 minutes). Store resetTokenExpiry: Date.now() + 3600000 and check it before accepting the token.',
      });
    }

    return findings;
  },
};
