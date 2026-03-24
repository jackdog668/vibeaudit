/**
 * Rule: supabase-service-key-client
 * Detects Supabase service_role key used in client-side code.
 * The service_role key bypasses all RLS policies.
 */

/** @typedef {import('./types.js').Rule} Rule */

const CLIENT_FILE = /(?:src\/|app\/|pages\/|components\/|hooks\/|lib\/client|utils\/client).*\.(js|ts|jsx|tsx)$/i;
const CLIENT_INDICATOR = /['"]use client['"]|import\s+.*from\s+['"]react['"]|useState|useEffect|onClick|onChange/;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.server\.|server\/|api\/|src\/rules\/)/i;

const SERVICE_KEY_PATTERNS = [
  /service_role/gi,
  /SUPABASE_SERVICE_ROLE/gi,
  /serviceRole/gi,
  /supabaseAdmin/gi,
];

/** @type {Rule} */
export const supabaseServiceKeyClient = {
  id: 'supabase-service-key-client',
  name: 'Supabase Service Key in Client',
  severity: 'critical',
  description: 'Detects Supabase service_role key used in client-side code.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    const isClient = CLIENT_FILE.test(file.relativePath) || CLIENT_INDICATOR.test(file.content);
    if (!isClient) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      for (const pattern of SERVICE_KEY_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          // Skip comments
          const trimmed = line.trim();
          if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

          findings.push({
            ruleId: 'supabase-service-key-client',
            ruleName: 'Supabase Service Key in Client',
            severity: 'critical',
            message: 'Supabase service_role key referenced in client-side code — bypasses all RLS.',
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: 'Never use the service_role key in client code. Use the anon key for client-side Supabase calls. Move service_role usage to server-side API routes.',
          });
          break;
        }
      }
    }

    return findings;
  },
};
