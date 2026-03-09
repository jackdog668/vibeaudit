# Contributing to Vibe Audit

Thanks for wanting to make AI-generated code safer. Here's how to contribute.

## Adding a New Rule

Every rule lives in `src/rules/` and follows the same interface:

```js
export const yourRule = {
  id: 'your-rule-id',        // kebab-case, unique
  name: 'Your Rule Name',    // Human-readable
  severity: 'critical',      // 'critical' | 'warning' | 'info'
  description: 'What this rule checks for.',
  check(file) {
    // file = { path, relativePath, content, lines }
    // Return an array of findings (see src/rules/types.js)
    return [];
  },
};
```

Then register it in `src/rules/index.js`.

## Rules for Rules

1. **Zero false positives over catching everything.** A rule that cries wolf gets disabled.
2. **Skip comments and documentation.** Don't flag `// TODO: add auth` as a missing auth issue.
3. **Redact secrets in evidence.** Never put the full secret in the finding output.
4. **Every finding needs a fix.** Tell the user exactly what to do, not just what's wrong.
5. **Write tests.** Every rule needs test cases for both detection and non-detection.

## Development

```bash
# Install dev dependencies
npm install

# Run tests
npm test

# Lint
npm run lint

# Self-audit (vibe-audit audits itself)
npm run audit:self
```

## Pull Request Process

1. Fork and create a feature branch.
2. Add your rule + tests.
3. Run `npm test` and `npm run lint`.
4. Open a PR with a clear description of what security issue your rule catches.

## Zero Dependencies Policy

The core scanner has **zero production dependencies**. This is intentional. Every dependency is a supply chain risk — and a security tool with supply chain vulnerabilities would be embarrassing.

If you need a library, consider whether Node.js built-ins can do the job first.

## Code of Conduct

Be respectful. We're all here to make the ecosystem safer. No gatekeeping, no elitism. If someone's first PR isn't perfect, help them improve it.
