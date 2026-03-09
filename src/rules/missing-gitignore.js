/**
 * Rule: missing-gitignore
 * Detects projects where .env files are not in .gitignore.
 *
 * The attack: Vibe coder creates .env, puts API keys in it,
 * runs "git add .", pushes to GitHub. Bots scrape GitHub for .env
 * files 24/7. By the time you notice, someone racked up $50K on AWS.
 * Even after deleting the file, it's in git history forever.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Files that should ALWAYS be in .gitignore. */
const MUST_IGNORE = [
  { pattern: '.env', description: 'Environment variables file' },
  { pattern: '.env.local', description: 'Local environment overrides' },
  { pattern: '.env.production', description: 'Production secrets' },
  { pattern: '.env.development', description: 'Development secrets' },
];

/** Other files that ideally should be ignored. */
const SHOULD_IGNORE = [
  { pattern: 'node_modules', description: 'Dependencies directory' },
  { pattern: '.DS_Store', description: 'macOS metadata' },
];

/** @type {Rule} */
export const missingGitignore = {
  id: 'missing-gitignore',
  name: 'Missing .gitignore Entries',
  severity: 'critical',
  description: 'Detects .env and secret files not listed in .gitignore — one "git push" leaks all your keys.',

  check(file) {
    // Only check .gitignore files.
    if (file.relativePath !== '.gitignore') return [];

    const findings = [];
    const content = file.content.toLowerCase();
    const lines = content.split('\n').map((l) => l.trim());

    // Check each must-ignore pattern.
    for (const { pattern, description } of MUST_IGNORE) {
      const lowerPattern = pattern.toLowerCase();
      const isIgnored = lines.some((line) => {
        if (line.startsWith('#')) return false;
        return (
          line === lowerPattern ||
          line === lowerPattern + '/' ||
          line === `*${lowerPattern.slice(lowerPattern.lastIndexOf('.'))}` ||
          line.includes('.env')
        );
      });

      if (!isIgnored) {
        findings.push({
          ruleId: 'missing-gitignore',
          ruleName: 'Missing .gitignore Entries',
          severity: 'critical',
          message: `"${pattern}" (${description}) is not in .gitignore — will be committed to git.`,
          file: file.relativePath,
          line: 1,
          evidence: `Missing: ${pattern}`,
          fix: `Add "${pattern}" to your .gitignore file immediately. If you've already committed it, the file is in git history even after deletion. Run: "git rm --cached ${pattern}" then add to .gitignore. If pushed to a public repo, rotate ALL secrets in that file — they are compromised.`,
        });
      }
    }

    // Check should-ignore patterns (warnings only).
    for (const { pattern, description } of SHOULD_IGNORE) {
      const lowerPattern = pattern.toLowerCase();
      const isIgnored = lines.some((line) => {
        if (line.startsWith('#')) return false;
        return line === lowerPattern || line === lowerPattern + '/' || line.startsWith(lowerPattern);
      });

      if (!isIgnored) {
        findings.push({
          ruleId: 'missing-gitignore',
          ruleName: 'Missing .gitignore Entries',
          severity: 'warning',
          message: `"${pattern}" (${description}) is not in .gitignore.`,
          file: file.relativePath,
          line: 1,
          evidence: `Missing: ${pattern}`,
          fix: `Add "${pattern}" to your .gitignore to keep your repo clean and avoid accidentally committing unnecessary or sensitive files.`,
        });
      }
    }

    return findings;
  },
};
