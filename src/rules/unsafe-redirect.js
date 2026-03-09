/**
 * Rule: unsafe-redirect
 * Detects unvalidated redirect URLs, especially in auth flows.
 *
 * The attack: /login?redirect=https://evil.com/steal-creds
 * After successful login, your app redirects the user (with fresh cookies)
 * to the attacker's site. The attacker's site looks identical to yours.
 * User thinks they need to log in again. Now the attacker has their password.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Redirect patterns using user input. */
const REDIRECT_PATTERNS = [
  // Server-side redirect from query/body param
  {
    regex: /res\.redirect\s*\(\s*(?:req\.query|query|req\.body|body|params|searchParams)\.(?:redirect|returnTo|return_to|returnUrl|return_url|next|callback|callbackUrl|callback_url|continue|goto|destination|target|url|redir)/gi,
    label: 'Server redirect using unvalidated user input — open redirect vulnerability',
  },
  // Next.js redirect from searchParams
  {
    regex: /redirect\s*\(\s*(?:searchParams|params|query)\.(?:redirect|returnTo|return_to|callbackUrl|callback_url|next|continue|goto)/gi,
    label: 'Redirect using unvalidated search parameter — open redirect risk',
  },
  // Building redirect URL from user input
  {
    regex: /(?:redirectUrl|returnUrl|callbackUrl|nextUrl|redirectTo)\s*=\s*(?:req\.query|query|searchParams\.get|req\.body|body)\./gi,
    label: 'Redirect URL sourced from user input — validate before redirecting',
  },
  // window.location or router.push from URL params (client-side)
  {
    regex: /(?:window\.location|router\.push|router\.replace|navigate)\s*[=(]\s*(?:searchParams|params|query)\.\w*(?:redirect|return|callback|next|goto|url)/gi,
    label: 'Client-side redirect from URL parameter — validate the destination',
  },
  // Header-based redirect
  {
    regex: /(?:setHeader|writeHead)\s*\([^)]*['"`]Location['"`]\s*,\s*(?:req\.query|query|req\.body|body|params)\./gi,
    label: 'Location header set from user input — open redirect',
  },
];

/** Validation indicators. */
const VALIDATION_INDICATORS = [
  /\.startsWith\s*\(\s*['"`]\//,  // Relative URL check
  /\.startsWith\s*\(\s*(?:process\.env|BASE_URL|APP_URL|SITE_URL)/i,
  /new\s+URL\s*\(.*\.(?:host|hostname|origin)\s*(?:===|!==)/i,
  /(?:allowedRedirects|allowed_redirects|safeRedirects|REDIRECT_WHITELIST|REDIRECT_ALLOWLIST)/i,
  /(?:isRelativeUrl|isSafeRedirect|isAllowedRedirect|validateRedirect|sanitizeRedirect)/i,
  /(?:url\.protocol|protocol\s*===\s*['"`]https)/i,
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const unsafeRedirect = {
  id: 'unsafe-redirect',
  name: 'Unsafe Redirect',
  severity: 'warning',
  description: 'Detects unvalidated redirect URLs from user input — enables phishing attacks in auth flows.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const hasValidation = VALIDATION_INDICATORS.some((p) => p.test(file.content));
    if (hasValidation) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label } of REDIRECT_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'unsafe-redirect',
            ruleName: 'Unsafe Redirect',
            severity: 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Validate redirect URLs before use: (1) Only allow relative paths (startsWith("/")). (2) If absolute URLs are needed, check against an allowlist of your own domains. (3) Never redirect to user-provided external URLs. Without validation, /login?redirect=https://evil.com sends authenticated users to the attacker's phishing site.`,
          });
        }
      }
    }

    return findings;
  },
};
