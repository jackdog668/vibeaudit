/**
 * Rule: graphql-introspection
 * Detects GraphQL introspection left enabled in production config.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

/** @type {Rule} */
export const graphqlIntrospection = {
  id: 'graphql-introspection',
  name: 'GraphQL Introspection Enabled',
  severity: 'warning',
  description: 'Detects GraphQL introspection enabled in production, exposing your entire schema.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:graphql|apollo|yoga|mercurius)/i.test(file.content)) return [];

    const findings = [];

    // introspection: true (without env check)
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (/introspection\s*:\s*true/i.test(line)) {
        // Check if it's conditional on NODE_ENV
        const context = file.lines.slice(Math.max(0, i - 3), i + 1).join('\n');
        if (/NODE_ENV|process\.env|development/i.test(context)) continue;

        findings.push({
          ruleId: 'graphql-introspection',
          ruleName: 'GraphQL Introspection Enabled',
          severity: 'warning',
          message: 'GraphQL introspection is unconditionally enabled — attackers can map your entire API.',
          file: file.relativePath,
          line: i + 1,
          evidence: line.trim().slice(0, 120),
          fix: 'Set introspection to only be enabled in development: introspection: process.env.NODE_ENV !== "production".',
        });
      }

      // playground/graphiql enabled
      if (/(?:playground|graphiql)\s*:\s*true/i.test(line)) {
        const context = file.lines.slice(Math.max(0, i - 3), i + 1).join('\n');
        if (/NODE_ENV|process\.env|development/i.test(context)) continue;

        findings.push({
          ruleId: 'graphql-introspection',
          ruleName: 'GraphQL Introspection Enabled',
          severity: 'warning',
          message: 'GraphQL playground/GraphiQL is unconditionally enabled in production.',
          file: file.relativePath,
          line: i + 1,
          evidence: line.trim().slice(0, 120),
          fix: 'Disable playground in production: playground: process.env.NODE_ENV === "development".',
        });
      }
    }

    return findings;
  },
};
