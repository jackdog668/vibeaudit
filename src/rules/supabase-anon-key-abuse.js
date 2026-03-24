/**
 * Rule: supabase-anon-key-abuse
 * Detects Supabase anon key used for operations that should require
 * the service_role key (e.g., admin operations, auth.admin).
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const ADMIN_PATTERNS = [
  { pattern: /\.auth\.admin\./g, label: 'auth.admin (requires service_role)' },
  { pattern: /\.rpc\s*\(\s*['"`](?:delete_user|admin_|manage_)/g, label: 'admin RPC function' },
  { pattern: /\.from\s*\(\s*['"`]auth\.users['"`]\s*\)/g, label: 'direct auth.users table access' },
];

/** @type {Rule} */
export const supabaseAnonKeyAbuse = {
  id: 'supabase-anon-key-abuse',
  name: 'Supabase Anon Key Abuse',
  severity: 'warning',
  description: 'Detects Supabase anon key used for admin operations that need service_role.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/supabase/i.test(file.content)) return [];

    // Only flag if file uses the anon key (not service_role)
    const usesAnon = /SUPABASE_ANON|supabaseClient|createClient\s*\(/i.test(file.content);
    const usesServiceRole = /service_role|SUPABASE_SERVICE_ROLE|supabaseAdmin/i.test(file.content);
    if (!usesAnon || usesServiceRole) return [];

    const findings = [];

    for (const { pattern, label } of ADMIN_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'supabase-anon-key-abuse',
          ruleName: 'Supabase Anon Key Abuse',
          severity: 'warning',
          message: `${label} called with anon key — this will fail or be restricted.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Use a server-side Supabase client with the service_role key for admin operations. Never expose service_role to the client.',
        });
      }
    }

    return findings;
  },
};
