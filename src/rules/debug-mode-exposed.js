/**
 * Rule: debug-mode-exposed
 * Detects debug/development mode left enabled in production config.
 *
 * The attack: Debug mode exposes stack traces, env vars, SQL queries,
 * route maps, and internal state. Next.js dev mode shows full source.
 * Express with NODE_ENV=development shows stack traces to users.
 * Django DEBUG=True shows every setting and installed app.
 */

/** @typedef {import('./types.js').Rule} Rule */

const DEBUG_PATTERNS = [
  // Hardcoded debug: true (only in config-like files, not in import/require)
  { regex: /^\s*(?:export\s+(?:default\s+)?)?(?:const\s+\w+\s*=\s*)?\{?[^}]*debug\s*:\s*true\b/gim, label: 'Debug mode enabled — may expose internal state in production' },
  // NODE_ENV hardcoded to development in non-.env files
  { regex: /NODE_ENV\s*=\s*['"`]development['"`]/gi, label: 'NODE_ENV hardcoded to development — debug features active in production' },
  // GraphQL playground/introspection enabled unconditionally
  { regex: /(?:playground|introspection)\s*:\s*true(?!\s*&&|\s*\?|\s*\|\|)/gi, label: 'GraphQL playground/introspection enabled unconditionally — full schema exposed' },
  // Django DEBUG=True
  { regex: /^DEBUG\s*=\s*True\b/gm, label: 'Django DEBUG=True — full error pages with settings exposed' },
  // Flask debug
  { regex: /app\.run\s*\([^)]*debug\s*=\s*True/gi, label: 'Flask running in debug mode — interactive debugger exposed' },
];

const CONFIG_FILES = /(?:config|settings|\.env|next\.config|nuxt\.config|vite\.config|app\.(js|ts)|server\.(js|ts)|index\.(js|ts))/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/|\.example|\.sample|\.development|\.dev\.|config\.dev|config\.local)/i;

/** @type {Rule} */
export const debugModeExposed = {
  id: 'debug-mode-exposed',
  name: 'Debug Mode Exposed',
  severity: 'warning',
  description: 'Detects debug/development mode flags that expose internal state, stack traces, and schema information in production.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      for (const { regex, label } of DEBUG_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'debug-mode-exposed',
            ruleName: 'Debug Mode Exposed',
            severity: 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Use environment variables for debug flags: "debug: process.env.NODE_ENV === 'development'". Never hardcode debug:true. Disable GraphQL introspection/playground in production. Debug mode exposes stack traces, internal routes, database queries, and environment variables to anyone.`,
          });
        }
      }
    }

    return findings;
  },
};
