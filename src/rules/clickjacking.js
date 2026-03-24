/**
 * Rule: clickjacking
 * Detects missing X-Frame-Options or CSP frame-ancestors headers that
 * leave the app vulnerable to clickjacking attacks.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const CONFIG_FILES = /(?:next\.config\.(js|ts|mjs)|server\.(js|ts)|app\.(js|ts)|vercel\.json|netlify\.toml|express|middleware)/i;

/** @type {Rule} */
export const clickjacking = {
  id: 'clickjacking',
  name: 'Clickjacking Protection Missing',
  severity: 'warning',
  description: 'Detects missing X-Frame-Options or CSP frame-ancestors in server/config files.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!CONFIG_FILES.test(file.relativePath)) return [];

    // Check if headers are set elsewhere
    const hasFrameOptions = /X-Frame-Options|frame-ancestors/i.test(file.content);
    const hasHelmet = /helmet\s*\(/i.test(file.content);
    if (hasFrameOptions || hasHelmet) return [];

    // Only flag files that set other headers (indicating headers are managed here)
    const setsHeaders = /(?:headers|setHeader|Content-Security-Policy|X-Content-Type)/i.test(file.content);
    if (!setsHeaders) return [];

    const lineIdx = file.lines.findIndex((l) => /headers|setHeader/i.test(l));

    return [{
      ruleId: 'clickjacking',
      ruleName: 'Clickjacking Protection Missing',
      severity: 'warning',
      message: 'Headers are configured but X-Frame-Options/frame-ancestors is missing — vulnerable to clickjacking.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      fix: 'Add X-Frame-Options: DENY header, or use CSP frame-ancestors: \'none\'. If using helmet: helmet() sets this by default.',
    }];
  },
};
