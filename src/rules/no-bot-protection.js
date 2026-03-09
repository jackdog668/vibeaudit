/**
 * Rule: no-bot-protection
 * Detects signup, registration, and form endpoints with no bot protection.
 *
 * The attack: Script creates 10,000 fake accounts per minute.
 * Spam your platform, abuse free tiers, pollute your database,
 * use your email sending quota. Bot farms run 24/7 and they WILL
 * find your unprotected signup endpoint.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Registration/signup endpoint patterns. */
const SIGNUP_PATTERNS = [
  { regex: /(?:app|router)\.post\s*\(\s*['"`]\/(?:api\/)?(?:register|signup|sign-up|create-account|join)['"`]/gi, label: 'Registration endpoint' },
  { regex: /export\s+(?:async\s+)?function\s+POST/g, label: 'POST handler', fileOnly: true },
  { regex: /(?:registerUser|signUpUser|handleSignup|handleRegister|createAccount)\s*\(/gi, label: 'Signup handler function' },
];

/** Bot protection indicators. */
const BOT_INDICATORS = [
  /(?:captcha|recaptcha|hcaptcha|turnstile|CAPTCHA)/i,
  /(?:g-recaptcha|h-captcha|cf-turnstile)/i,
  /(?:verify-recaptcha|verifyCaptcha|validateCaptcha|checkCaptcha)/i,
  /(?:honeypot|honey_pot|botField|bot_field)/i,
  /(?:arkose|funcaptcha|geetest)/i,
  /(?:rate-limiter-flexible|express-brute|express-slow-down)/i,
  /(?:bot-detect|isBot|is_bot|botDetect|bot_detect)/i,
];

const SIGNUP_FILES = /(?:register|signup|sign-up|create-account|join|auth)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const noBotProtection = {
  id: 'no-bot-protection',
  name: 'No Bot Protection',
  severity: 'warning',
  description: 'Detects signup/registration endpoints with no CAPTCHA or bot detection — vulnerable to automated account creation.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    const isSignupFile = SIGNUP_FILES.test(file.relativePath);

    let hasSignupHandler = false;
    let handlerLine = 0;

    for (const { regex, fileOnly } of SIGNUP_PATTERNS) {
      if (fileOnly && !isSignupFile) continue;
      regex.lastIndex = 0;
      const match = regex.exec(file.content);
      if (match) {
        hasSignupHandler = true;
        handlerLine = file.content.slice(0, match.index).split('\n').length;
        break;
      }
    }

    if (!hasSignupHandler) return [];
    if (BOT_INDICATORS.some((p) => p.test(file.content))) return [];

    return [{
      ruleId: 'no-bot-protection',
      ruleName: 'No Bot Protection',
      severity: 'warning',
      message: 'Signup/registration endpoint has no CAPTCHA or bot detection — bots can create unlimited fake accounts.',
      file: file.relativePath,
      line: handlerLine,
      evidence: file.lines[handlerLine - 1]?.trim().slice(0, 120),
      fix: `Add bot protection to signup endpoints. Options: (1) Google reCAPTCHA v3 (invisible). (2) Cloudflare Turnstile (privacy-friendly). (3) Honeypot fields. (4) Email verification before activation. Without this, bots create thousands of fake accounts to spam your platform.`,
    }];
  },
};
