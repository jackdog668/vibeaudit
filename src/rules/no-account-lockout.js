/**
 * Rule: no-account-lockout
 * Detects login/auth endpoints without brute force protection.
 *
 * The attack: Script tries 10,000 passwords per second against your
 * login endpoint. No lockout, no CAPTCHA, no exponential backoff.
 * Global rate limiting helps but isn't enough — you need per-user
 * throttling on auth endpoints specifically.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Login/auth handler patterns. */
const LOGIN_PATTERNS = [
  // Route handler for login/signin/authenticate
  {
    regex: /(?:app|router)\.post\s*\(\s*['"`]\/(?:api\/)?(?:login|signin|sign-in|authenticate|auth\/login)['"`]/gi,
    label: 'Login endpoint',
  },
  // Next.js auth route
  {
    regex: /export\s+(?:async\s+)?function\s+POST/g,
    label: 'POST handler',
    fileOnly: true,
  },
  // Password comparison (indicates auth logic)
  {
    regex: /(?:bcrypt|argon2|scrypt)\.(?:compare|verify)\s*\(/gi,
    label: 'Password verification',
  },
  // signIn function (NextAuth, etc.)
  {
    regex: /(?:signIn|authenticateUser|verifyCredentials|checkPassword)\s*\(/gi,
    label: 'Auth function call',
  },
];

/** Brute force protection indicators. */
const LOCKOUT_INDICATORS = [
  /(?:lockout|lock_out|lockedOut|locked_out|accountLocked|account_locked)/i,
  /(?:failedAttempts|failed_attempts|loginAttempts|login_attempts|attemptCount)/i,
  /(?:maxAttempts|max_attempts|MAX_LOGIN_ATTEMPTS)/i,
  /(?:exponentialBackoff|backoff|cooldown|throttle)/i,
  /(?:captcha|recaptcha|hcaptcha|turnstile|CAPTCHA)/i,
  /(?:rateLimit|rateLimiter).*(?:login|auth|signin)/i,
  /(?:login|auth|signin).*(?:rateLimit|rateLimiter)/i,
  /(?:bruteForce|brute_force|brute-force)/i,
  /(?:express-brute|rate-limiter-flexible)/i,
];

/** Auth-related files. */
const AUTH_FILES = /(?:auth|login|signin|sign-in|credentials|session)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const noAccountLockout = {
  id: 'no-account-lockout',
  name: 'No Account Lockout',
  severity: 'warning',
  description: 'Detects login endpoints without brute force protection — unlimited password attempts.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    // Must be an auth-related file.
    const isAuthFile = AUTH_FILES.test(file.relativePath);

    // Check for login handler patterns.
    let hasLoginHandler = false;
    let handlerLine = 0;

    for (const { regex, label, fileOnly } of LOGIN_PATTERNS) {
      if (fileOnly && !isAuthFile) continue;
      regex.lastIndex = 0;
      const match = regex.exec(file.content);
      if (match) {
        hasLoginHandler = true;
        const upToMatch = file.content.slice(0, match.index);
        handlerLine = upToMatch.split('\n').length;
        break;
      }
    }

    if (!hasLoginHandler) return [];

    // Check for brute force protection.
    const hasLockout = LOCKOUT_INDICATORS.some((p) => p.test(file.content));
    if (hasLockout) return [];

    return [
      {
        ruleId: 'no-account-lockout',
        ruleName: 'No Account Lockout',
        severity: 'warning',
        message: 'Login endpoint has no brute force protection — unlimited password attempts allowed.',
        file: file.relativePath,
        line: handlerLine,
        evidence: file.lines[handlerLine - 1]?.trim().slice(0, 120),
        fix: `Add brute force protection to login endpoints: (1) Track failed attempts per user/IP. (2) Lock accounts after 5-10 failed attempts. (3) Add exponential backoff (1s, 2s, 4s, 8s delays). (4) Consider CAPTCHA after 3 failures. Global rate limiting alone isn't enough — an attacker can distribute attempts across IPs.`,
      },
    ];
  },
};
