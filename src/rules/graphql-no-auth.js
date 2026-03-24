/**
 * Rule: graphql-no-auth
 * Detects GraphQL resolvers without authentication checks.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const RESOLVER_PATTERNS = [
  /(?:Query|Mutation)\s*:\s*\{/g,
  /(?:resolvers)\s*[:=]\s*\{/g,
];

const AUTH_INDICATORS = /(?:getServerSession|getSession|auth\(\)|requireAuth|isAuthenticated|authenticate|withAuth|getToken|verifyToken|currentUser|getUser|context\.user|ctx\.user|context\.auth|ctx\.auth|jwt\.verify|verifyIdToken)/i;

/** @type {Rule} */
export const graphqlNoAuth = {
  id: 'graphql-no-auth',
  name: 'GraphQL No Authentication',
  severity: 'critical',
  description: 'Detects GraphQL resolvers without authentication checks.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:graphql|resolver|Query|Mutation)/i.test(file.content)) return [];

    // Is this a resolver file?
    let isResolverFile = false;
    for (const pattern of RESOLVER_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(file.content)) {
        isResolverFile = true;
        break;
      }
    }
    if (!isResolverFile) return [];

    // Check for auth in the file
    if (AUTH_INDICATORS.test(file.content)) return [];

    const lineIdx = file.lines.findIndex((l) => /(?:Query|Mutation)\s*:\s*\{/.test(l));

    return [{
      ruleId: 'graphql-no-auth',
      ruleName: 'GraphQL No Authentication',
      severity: 'critical',
      message: 'GraphQL resolvers have no authentication checks — any user can call any query/mutation.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Check authentication in resolvers: const user = context.user; if (!user) throw new AuthenticationError("Not authenticated"). Add auth middleware or check context.user at the top of each resolver.',
    }];
  },
};
