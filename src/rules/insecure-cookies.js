/**
 * Rule: insecure-cookies
 * Detects cookies set without httpOnly, secure, or sameSite flags.
 *
 * The attack: Cookie without httpOnly → any XSS script reads the session
 * token with document.cookie. Without secure → sent over HTTP, sniffable.
 * Without sameSite → CSRF attacks from external sites.
 * DevTools → Application → Cookies shows all of this.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Cookie-setting patterns. */
const COOKIE_SET_PATTERNS = [
  // Express res.cookie without options or with incomplete options
  {
    regex: /res\.cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,)]+\s*\)/g,
    label: 'Cookie set with no security options (missing httpOnly, secure, sameSite)',
  },
  // Express res.cookie with options object
  {
    regex: /res\.cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,]+,\s*\{([^}]*)\}/g,
    label: 'cookie-with-options',
    checkOptions: true,
  },
  // Set-Cookie header directly
  {
    regex: /['"`]Set-Cookie['"`]\s*,\s*['"`][^'"`]+['"`]/gi,
    label: 'Raw Set-Cookie header — verify security flags are set',
    severity: 'warning',
  },
  // document.cookie assignment
  {
    regex: /document\.cookie\s*=\s*(?!.*(?:httponly|secure|samesite))/gi,
    label: 'Client-side cookie set without security flags',
    severity: 'warning',
  },
];

/** Required cookie flags. */
const REQUIRED_FLAGS = ['httponly', 'secure', 'samesite'];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const insecureCookies = {
  id: 'insecure-cookies',
  name: 'Insecure Cookie Config',
  severity: 'warning',
  description: 'Detects cookies set without httpOnly, secure, or sameSite flags — session tokens visible in DevTools and vulnerable to XSS/CSRF.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    if (!file.content.includes('cookie') && !file.content.includes('Cookie')) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, checkOptions, severity } of COOKIE_SET_PATTERNS) {
        regex.lastIndex = 0;
        const match = regex.exec(line);
        if (!match) continue;

        if (checkOptions) {
          // Check what flags are present in the options object.
          const options = match[1]?.toLowerCase() || '';
          const missing = REQUIRED_FLAGS.filter((f) => !options.includes(f));
          if (missing.length === 0) continue;

          findings.push({
            ruleId: 'insecure-cookies',
            ruleName: 'Insecure Cookie Config',
            severity: 'warning',
            message: `Cookie missing security flags: ${missing.join(', ')}`,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Set all security flags: res.cookie("name", value, { httpOnly: true, secure: true, sameSite: "lax" }). httpOnly prevents JavaScript access (XSS protection). secure ensures HTTPS only. sameSite prevents cross-site sending (CSRF protection).`,
          });
        } else if (label.includes('no security options')) {
          findings.push({
            ruleId: 'insecure-cookies',
            ruleName: 'Insecure Cookie Config',
            severity: 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Always set security flags: res.cookie("name", value, { httpOnly: true, secure: true, sameSite: "lax" }). Without these, cookies are readable by scripts, sent over HTTP, and vulnerable to cross-site attacks.`,
          });
        } else {
          findings.push({
            ruleId: 'insecure-cookies',
            ruleName: 'Insecure Cookie Config',
            severity: severity || 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Ensure cookies include httpOnly, secure, and sameSite flags. Check DevTools → Application → Cookies to verify flags are set correctly in production.`,
          });
        }
      }
    }

    return findings;
  },
};
