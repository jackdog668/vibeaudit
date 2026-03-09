/**
 * Rule: timing-attack
 * Detects string comparison (===) for tokens and secrets instead of
 * constant-time comparison.
 *
 * The attack: === short-circuits on first different character.
 * Attacker measures response time: "a..." takes 1ms, "b..." takes 0.5ms →
 * first char is "a". Repeat for each position. Cracks your token
 * character by character. crypto.timingSafeEqual prevents this.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Token/secret comparison with === instead of timingSafeEqual. */
const TIMING_PATTERNS = [
  // Direct comparison of token/secret/key variables
  {
    regex: /(?:token|secret|key|signature|hash|digest|hmac|apiKey|api_key|webhook_secret|signing)\s*(?:===|!==|==|!=)\s*(?:expected|stored|correct|valid|provided|received|incoming|req\.|body\.|query\.|header)/gi,
    label: 'Token/secret compared with === — vulnerable to timing attack',
  },
  {
    regex: /(?:expected|stored|correct|valid|provided)\s*(?:===|!==|==|!=)\s*(?:token|secret|key|signature|hash|digest|hmac|apiKey)/gi,
    label: 'Secret compared with === — vulnerable to timing attack',
  },
  // Webhook signature verification with ===
  {
    regex: /(?:signature|sig|hmac)\s*===\s*(?:expected|computed|calculated)/gi,
    label: 'Webhook signature compared with === — use crypto.timingSafeEqual instead',
  },
  // Reset token / verify token comparison
  {
    regex: /(?:resetToken|verifyToken|confirmToken|inviteToken|otpCode)\s*(?:===|!==)\s*/gi,
    label: 'Security token compared with === — vulnerable to timing attack',
  },
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const timingAttack = {
  id: 'timing-attack',
  name: 'Timing Attack',
  severity: 'warning',
  description: 'Detects string === comparison for tokens/secrets — attackers can extract the value character by character by measuring response times.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    // Only check files that deal with tokens/auth.
    if (!/(?:token|secret|signature|hmac|verify|auth|webhook)/i.test(file.content)) return [];

    // If timingSafeEqual is already imported, skip.
    if (/timingSafeEqual/i.test(file.content)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label } of TIMING_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'timing-attack',
            ruleName: 'Timing Attack',
            severity: 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Use crypto.timingSafeEqual() instead of === for comparing tokens, secrets, and signatures. The === operator short-circuits on the first different character, leaking timing information. Example: crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)).`,
          });
        }
      }
    }

    return findings;
  },
};
