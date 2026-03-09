/**
 * Rule: insecure-jwt
 * Detects weak JWT signing secrets, missing algorithm pinning, and no expiry.
 *
 * The attack: jwt.sign(payload, "secret") → attacker cracks "secret"
 * in seconds with a brute force tool → forges admin tokens at will.
 * Every AI tutorial uses "secret" as the example and vibe coders copy it.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Weak/default JWT signing secrets. */
const WEAK_SECRET_PATTERNS = [
  // jwt.sign with short string literal
  {
    regex: /jwt\.sign\s*\([^,]+,\s*['"`]([^'"`]{1,20})['"`]/gi,
    label: 'JWT signed with a short/weak secret — crackable in seconds',
    severity: 'critical',
  },
  // Common default secrets
  {
    regex: /jwt\.sign\s*\([^,]+,\s*['"`](?:secret|password|key|token|jwt[_-]?secret|my[_-]?secret|your[_-]?secret|change[_-]?me|test|dev|1234|admin)['"`]/gi,
    label: 'JWT signed with a common default secret — trivially crackable',
    severity: 'critical',
  },
];

/** Missing algorithm pinning on verify. */
const ALGORITHM_PATTERNS = [
  // jwt.verify without algorithms option
  {
    regex: /jwt\.verify\s*\(\s*[^,]+,\s*[^,]+\s*\)/g,
    label: 'jwt.verify without algorithms option — vulnerable to algorithm confusion attacks',
    severity: 'warning',
  },
];

/** Missing expiry on sign. */
const NO_EXPIRY_PATTERN = /jwt\.sign\s*\(\s*(?:(?!expiresIn|exp).)*\)/gi;

/** JWT-related files. */
const JWT_FILES = /(?:auth|jwt|token|session|middleware|login|verify)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const insecureJwt = {
  id: 'insecure-jwt',
  name: 'Insecure JWT',
  severity: 'critical',
  description: 'Detects weak JWT secrets, missing algorithm pinning, and tokens without expiry.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    // Only check files that reference JWT.
    if (!file.content.includes('jwt')) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      // Weak secrets
      for (const { regex, label, severity } of WEAK_SECRET_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'insecure-jwt',
            ruleName: 'Insecure JWT',
            severity,
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.replace(/['"`][^'"`]+['"`]/, '"***REDACTED***"').slice(0, 120),
            fix: `Use a long (32+ character), random signing secret stored in an environment variable. Generate one with: "node -e \\"console.log(require('crypto').randomBytes(64).toString('hex'))\\"". Never hardcode JWT secrets.`,
          });
        }
      }

      // Missing algorithm pinning
      for (const { regex, label, severity } of ALGORITHM_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'insecure-jwt',
            ruleName: 'Insecure JWT',
            severity,
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Always pin the algorithm in jwt.verify(): jwt.verify(token, secret, { algorithms: ["HS256"] }). Without this, attackers can switch the algorithm to "none" or use your public key to forge tokens.`,
          });
        }
      }
    }

    // File-level check: jwt.sign without expiresIn
    NO_EXPIRY_PATTERN.lastIndex = 0;
    if (NO_EXPIRY_PATTERN.test(file.content) && !file.content.includes('expiresIn') && !file.content.includes('"exp"')) {
      findings.push({
        ruleId: 'insecure-jwt',
        ruleName: 'Insecure JWT',
        severity: 'warning',
        message: 'JWT signed without an expiration time — tokens are valid forever if stolen.',
        file: file.relativePath,
        line: 1,
        fix: `Always set an expiry: jwt.sign(payload, secret, { expiresIn: "1h" }). Without expiry, a stolen token grants permanent access.`,
      });
    }

    return findings;
  },
};
