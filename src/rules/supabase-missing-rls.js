/**
 * Rule: supabase-missing-rls
 * Detects Supabase usage patterns where Row Level Security (RLS) is likely
 * missing — the #1 Supabase security failure for vibe coders.
 *
 * Checks for:
 * - Direct table access without RLS hints in migration files
 * - Supabase client calls that bypass RLS (service_role usage patterns)
 * - SQL migrations that create tables without enabling RLS
 */

/** @typedef {import('./types.js').Rule} Rule */

const MIGRATION_FILE = /(?:migrations?|supabase)\/.*\.sql$/i;
const SUPABASE_FILE = /(?:supabase|database|db)\.(js|ts|jsx|tsx)$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const CREATE_TABLE = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)/gi;
const ENABLE_RLS = /ALTER\s+TABLE\s+(?:public\.)?(\w+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
const RLS_POLICY = /CREATE\s+POLICY/gi;

/** @type {Rule} */
export const supabaseMissingRls = {
  id: 'supabase-missing-rls',
  name: 'Supabase Missing RLS',
  severity: 'critical',
  description: 'Detects Supabase tables that may lack Row Level Security policies.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    const findings = [];

    // Check SQL migration files for tables without RLS
    if (MIGRATION_FILE.test(file.relativePath)) {
      const tables = [];
      CREATE_TABLE.lastIndex = 0;
      let match;
      while ((match = CREATE_TABLE.exec(file.content)) !== null) {
        tables.push({ name: match[1], line: file.content.slice(0, match.index).split('\n').length });
      }

      if (tables.length > 0) {
        ENABLE_RLS.lastIndex = 0;
        const rlsEnabled = new Set();
        while ((match = ENABLE_RLS.exec(file.content)) !== null) {
          rlsEnabled.add(match[1].toLowerCase());
        }

        for (const table of tables) {
          if (!rlsEnabled.has(table.name.toLowerCase())) {
            findings.push({
              ruleId: 'supabase-missing-rls',
              ruleName: 'Supabase Missing RLS',
              severity: 'critical',
              message: `Table "${table.name}" is created without enabling Row Level Security.`,
              file: file.relativePath,
              line: table.line,
              evidence: `CREATE TABLE ${table.name}`,
              fix: `Add after the CREATE TABLE: ALTER TABLE ${table.name} ENABLE ROW LEVEL SECURITY; then create appropriate policies with CREATE POLICY.`,
            });
          }
        }

        // Check for no policies at all
        RLS_POLICY.lastIndex = 0;
        if (tables.length > 0 && !RLS_POLICY.test(file.content) && rlsEnabled.size > 0) {
          findings.push({
            ruleId: 'supabase-missing-rls',
            ruleName: 'Supabase Missing RLS',
            severity: 'critical',
            message: 'RLS is enabled but no policies are defined — all access is denied by default, but this may be unintentional.',
            file: file.relativePath,
            line: 1,
            fix: 'Add CREATE POLICY statements to define who can SELECT, INSERT, UPDATE, DELETE on each table.',
          });
        }
      }
    }

    // Check JS/TS files for patterns suggesting missing RLS
    if (SUPABASE_FILE.test(file.relativePath) || /supabase/i.test(file.content)) {
      // Detect .from('table').select/insert/update/delete without RLS context
      const rpcBypass = /\.rpc\s*\(\s*['"`]\w+['"`]\s*,/g;
      rpcBypass.lastIndex = 0;
      let m;
      while ((m = rpcBypass.exec(file.content)) !== null) {
        const before = file.content.slice(Math.max(0, m.index - 200), m.index);
        if (/service_role|supabaseAdmin|serviceRole/i.test(before)) {
          const lineNum = file.content.slice(0, m.index).split('\n').length;
          findings.push({
            ruleId: 'supabase-missing-rls',
            ruleName: 'Supabase Missing RLS',
            severity: 'critical',
            message: 'RPC call using service_role key bypasses RLS — ensure this is intentional and server-only.',
            file: file.relativePath,
            line: lineNum,
            evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
            fix: 'Use the anon key for client-side calls. Only use service_role in trusted server-side code.',
          });
        }
      }
    }

    return findings;
  },
};
