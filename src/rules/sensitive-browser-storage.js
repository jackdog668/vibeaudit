/**
 * Rule: sensitive-browser-storage
 * Detects sensitive data being stored in localStorage or sessionStorage.
 *
 * The DevTools attack: Application tab → Local Storage → copy the JWT/token.
 * Now you ARE that user from any browser.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Patterns that store sensitive data in browser storage. */
const STORAGE_PATTERNS = [
  // Storing tokens
  {
    regex: /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`][^'"`]*(?:token|jwt|auth|session|credential|apiKey|api_key|secret|password|bearer)[^'"`]*['"`]/gi,
    label: 'Sensitive data stored in browser storage — visible in DevTools → Application tab',
  },
  // Direct property assignment
  {
    regex: /(?:localStorage|sessionStorage)\s*\[\s*['"`][^'"`]*(?:token|jwt|auth|session|credential|apiKey|api_key|secret|password|bearer)[^'"`]*['"`]\s*\]\s*=/gi,
    label: 'Sensitive data stored in browser storage via bracket notation',
  },
  // Storing full user objects (may contain sensitive fields)
  {
    regex: /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`][^'"`]*(?:user|profile|account)[^'"`]*['"`]\s*,\s*JSON\.stringify/gi,
    label: 'User object serialized to browser storage — may contain sensitive fields visible in DevTools',
    severity: 'warning',
  },
];

/** @type {Rule} */
export const sensitiveBrowserStorage = {
  id: 'sensitive-browser-storage',
  name: 'Sensitive Browser Storage',
  severity: 'critical',
  description: 'Detects tokens, credentials, and PII stored in localStorage/sessionStorage — all visible in DevTools Application tab.',

  check(file) {
    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, severity } of STORAGE_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'sensitive-browser-storage',
            ruleName: 'Sensitive Browser Storage',
            severity: severity || 'critical',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Don't store tokens or sensitive data in localStorage/sessionStorage. Use httpOnly cookies (set by the server) for auth tokens — they're invisible to JavaScript and DevTools Application tab. For session data, keep it server-side.`,
          });
        }
      }
    }

    return findings;
  },
};
