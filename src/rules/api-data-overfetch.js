/**
 * Rule: api-data-overfetch
 * Detects API routes that return full database objects without field filtering.
 *
 * The DevTools attack: Network tab → click any API request → Response tab →
 * see passwordHash, SSN, stripeId, internal IDs, etc. that the UI doesn't show.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Patterns that indicate returning raw database objects without selecting fields. */
const OVERFETCH_PATTERNS = [
  // Returning entire Firestore/MongoDB documents
  {
    regex: /(?:res\.json|Response\.json|return\s+(?:NextResponse\.)?json)\s*\([^)]*(?:\.data\(\)|\.docs|\.val\(\)|findOne|findById|getDoc|getDocs|find\(\))/gi,
    label: 'Raw database object returned in API response — may expose sensitive fields in DevTools Network tab',
  },
  // Prisma findUnique/findMany without select
  {
    regex: /(?:findUnique|findMany|findFirst)\s*\(\s*\{(?:(?!select|include).)*\}\s*\)/gi,
    label: 'Prisma query without select/include — returns ALL fields, potentially exposing sensitive data',
  },
  // Mongoose .find() without .select()
  {
    regex: /\.find\([^)]*\)\s*(?!\s*\.select)/g,
    label: 'Database query without field selection — consider selecting only needed fields',
    severity: 'info',
  },
  // Spreading user/account objects into response
  {
    regex: /(?:res\.json|Response\.json|return\s+(?:NextResponse\.)?json)\s*\([^)]*\.\.\.(?:user|account|profile|customer|member)/gi,
    label: 'Full user/account object spread into API response — may include passwordHash, tokens, or PII',
  },
];

/** Only check server-side API files. */
const API_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__)/i;

/** @type {Rule} */
export const apiDataOverfetch = {
  id: 'api-data-overfetch',
  name: 'API Data Overfetching',
  severity: 'warning',
  description: 'Detects API routes that return full database objects — extra fields are visible in DevTools Network tab.',

  check(file) {
    if (!API_FILES.test(file.relativePath)) return [];
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label, severity } of OVERFETCH_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'api-data-overfetch',
            ruleName: 'API Data Overfetching',
            severity: severity || 'warning',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Only return the fields the client actually needs. Use select/projection in your database query, or map the result to a DTO (data transfer object) before sending. Anyone can see the full response in DevTools → Network → click request → Response tab.`,
          });
        }
      }
    }

    return findings;
  },
};
