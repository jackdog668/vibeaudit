/**
 * Rule: no-pagination
 * Detects API endpoints that query all records with no limit/pagination.
 *
 * The attack: Call /api/users → get every user in your database in one response.
 * Your DB melts, your server OOMs, and someone just scraped your entire dataset.
 * Or: /api/posts → 50,000 posts in one JSON payload → browser tab crashes.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Patterns that fetch all records without limits. */
const UNBOUNDED_QUERY_PATTERNS = [
  // Firestore: getDocs with no limit()
  {
    regex: /getDocs\s*\(\s*(?:collection|query)\s*\([^)]*\)\s*\)/gi,
    label: 'Firestore getDocs with no limit() — returns all matching documents',
    needsLimitCheck: 'limit(',
  },
  // Prisma: findMany with no take
  {
    regex: /\.findMany\s*\(\s*(?:\{(?:(?!take|first|last).)*\}|\s*\))/gi,
    label: 'Prisma findMany with no take/cursor — returns all matching records',
    needsLimitCheck: 'take:',
  },
  // Mongoose: find() with no limit()
  {
    regex: /\.find\s*\([^)]*\)\s*(?!.*\.limit)/g,
    label: 'Mongoose find() with no limit() — returns all matching documents',
    needsLimitCheck: '.limit(',
  },
  // Knex/SQL: SELECT without LIMIT
  {
    regex: /\.select\s*\([^)]*\)\s*(?!.*\.limit)/g,
    label: 'Query builder select without limit — may return unbounded results',
    needsLimitCheck: '.limit(',
    severity: 'info',
  },
  // Raw SQL without LIMIT
  {
    regex: /(?:query|execute|sql)\s*\(\s*['"`]SELECT\s+(?:(?!LIMIT).)*['"`]\s*\)/gi,
    label: 'SQL SELECT without LIMIT clause — returns all matching rows',
    needsLimitCheck: 'LIMIT',
  },
  // Firestore .get() on collection reference (gets everything)
  {
    regex: /(?:collection|db\.collection)\s*\([^)]*\)\s*\.get\s*\(\s*\)/gi,
    label: 'Firestore collection().get() with no query constraints — fetches ALL documents',
  },
  // Supabase: select without limit
  {
    regex: /\.from\s*\([^)]*\)\s*\.select\s*\([^)]*\)\s*(?!.*\.limit|.*\.range)/g,
    label: 'Supabase query without limit/range — returns all matching rows',
    needsLimitCheck: '.limit(',
  },
];

/** Only check API/server files. */
const API_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/|controllers\/)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** Indicators that pagination IS implemented. */
const PAGINATION_INDICATORS = [
  /(?:page|pageSize|page_size|perPage|per_page|pageNumber|page_number)/i,
  /(?:offset|cursor|startAfter|startAt|endBefore|endAt)/i,
  /(?:skip|take|first|last|limit)\s*[:=]/i,
  /\.limit\s*\(/i,
  /LIMIT\s+\d/i,
  /\.range\s*\(/i,
  /(?:paginate|pagination|Pagination)/i,
];

/** @type {Rule} */
export const noPagination = {
  id: 'no-pagination',
  name: 'No Pagination',
  severity: 'warning',
  description: 'Detects API endpoints that return all records with no pagination or limits — enables data scraping and DoS.',

  check(file) {
    if (!API_FILES.test(file.relativePath)) return [];
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    // If file already has pagination patterns, it's likely handled.
    const hasPagination = PAGINATION_INDICATORS.some((p) => p.test(file.content));
    if (hasPagination) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, severity } of UNBOUNDED_QUERY_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'no-pagination',
            ruleName: 'No Pagination',
            severity: severity || 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Always add pagination or limits to list endpoints. Use limit/offset, cursor-based pagination, or at minimum a hard cap (e.g., .limit(100)). Without limits: (1) anyone can scrape your entire database in one request, (2) large result sets crash your server or client, (3) it's a trivial DoS vector.`,
          });
        }
      }
    }

    return findings;
  },
};
