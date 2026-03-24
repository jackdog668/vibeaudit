/**
 * Rule: graphql-depth-limit
 * Detects GraphQL servers without query depth or complexity limits,
 * making them vulnerable to DoS via deeply nested queries.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

const GRAPHQL_SERVER_SETUP = /(?:ApolloServer|createYoga|mercurius|makeExecutableSchema|buildSchema|new\s+GraphQLSchema)/i;

/** @type {Rule} */
export const graphqlDepthLimit = {
  id: 'graphql-depth-limit',
  name: 'GraphQL No Depth Limit',
  severity: 'warning',
  description: 'Detects GraphQL servers without query depth or complexity limits.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!GRAPHQL_SERVER_SETUP.test(file.content)) return [];

    const hasDepthLimit = /depthLimit|depth[_-]?limit|maxDepth|queryDepth|graphql-depth-limit/i.test(file.content);
    const hasComplexityLimit = /complexityLimit|query[_-]?complexity|costAnalysis|maxComplexity/i.test(file.content);

    if (hasDepthLimit || hasComplexityLimit) return [];

    const lineIdx = file.lines.findIndex((l) => GRAPHQL_SERVER_SETUP.test(l));

    return [{
      ruleId: 'graphql-depth-limit',
      ruleName: 'GraphQL No Depth Limit',
      severity: 'warning',
      message: 'GraphQL server has no query depth or complexity limit — vulnerable to DoS via nested queries.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Add a depth limit plugin: npm install graphql-depth-limit, then add validationRules: [depthLimit(10)] to your server config. Consider also adding query complexity analysis.',
    }];
  },
};
