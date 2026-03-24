/**
 * Rule: vercel-env-leak
 * Detects server-only secrets exposed with NEXT_PUBLIC_ prefix in
 * vercel.json, .env files, or code references.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const ENV_FILES = /(?:vercel\.json|\.env(?:\.\w+)?|next\.config\.(js|ts|mjs))$/i;

const SENSITIVE_NAMES = /(?:SECRET|PRIVATE|PASSWORD|CREDENTIAL|DATABASE_URL|SERVICE_ROLE|ADMIN_KEY|API_SECRET|JWT_SECRET|SIGNING_KEY|ENCRYPTION_KEY)/i;

/** @type {Rule} */
export const vercelEnvLeak = {
  id: 'vercel-env-leak',
  name: 'Vercel Environment Variable Leak',
  severity: 'critical',
  description: 'Detects server-only secrets exposed via NEXT_PUBLIC_ prefix.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!ENV_FILES.test(file.relativePath) && !/NEXT_PUBLIC_/i.test(file.content)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const match = line.match(/NEXT_PUBLIC_(\w+)/);
      if (!match) continue;

      const varName = match[1];
      if (SENSITIVE_NAMES.test(varName)) {
        findings.push({
          ruleId: 'vercel-env-leak',
          ruleName: 'Vercel Environment Variable Leak',
          severity: 'critical',
          message: `NEXT_PUBLIC_${varName} exposes a server-only secret to the browser.`,
          file: file.relativePath,
          line: i + 1,
          evidence: `NEXT_PUBLIC_${varName}`,
          fix: `Remove the NEXT_PUBLIC_ prefix. Access this secret only in server-side code via process.env.${varName}.`,
        });
      }
    }

    return findings;
  },
};
