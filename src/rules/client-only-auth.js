/**
 * Rule: client-only-auth
 * Detects authentication/authorization checks that only exist on the client.
 *
 * The DevTools attack: Open Console → fetch("/api/admin/data") → access granted
 * because the server never checks auth, only the React component does.
 */

/** @typedef {import('./types.js').Rule} Rule */

/**
 * Patterns that indicate client-side-only auth guards.
 * These protect the UI but not the data.
 */
const CLIENT_AUTH_GUARD_PATTERNS = [
  // React/Next.js client-side redirects based on auth
  {
    regex: /if\s*\(\s*!(?:user|session|isAuthenticated|isLoggedIn|isAuthed|auth|currentUser)\s*\)\s*(?:return\s+(?:null|<Navigate|<Redirect)|(?:router|navigate|redirect|window\.location)\s*[\.(])/gi,
    label: 'Client-side auth redirect — only hides UI, does not protect data',
  },
  // useEffect-based auth check with redirect
  {
    regex: /useEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*(?:!user|!session|!auth|!isAuthenticated)[^}]*(?:router\.push|navigate|redirect|window\.location)/gi,
    label: 'Auth check in useEffect — runs client-side only, server data is still exposed',
  },
  // Conditional rendering hiding admin/protected content
  {
    regex: /\{(?:isAdmin|isOwner|user\.role\s*===?\s*['"`]admin['"`]|hasPermission)\s*&&\s*[(<]/gi,
    label: 'Admin content hidden via conditional render — visible by calling API directly in DevTools',
  },
  // Protected route wrapper components (common in React Router)
  {
    regex: /(?:ProtectedRoute|PrivateRoute|AuthGuard|RequireAuth)\s*[=:]/gi,
    label: 'Client-side route guard component — ensure matching server-side auth exists',
    severity: 'warning',
  },
];

/** Only check client-side component files. */
const COMPONENT_FILE_PATTERNS = /\.(?:jsx|tsx|vue|svelte)$|(?:^src\/|^app\/|^pages\/(?!api\/))/i;

/** @type {Rule} */
export const clientOnlyAuth = {
  id: 'client-only-auth',
  name: 'Client-Only Auth Guards',
  severity: 'warning',
  description: 'Detects auth checks that only exist on the client side. DevTools Console can bypass these entirely.',

  check(file) {
    if (!COMPONENT_FILE_PATTERNS.test(file.relativePath)) return [];

    const findings = [];

    // Check the full content for multi-line patterns.
    for (const { regex, label, severity } of CLIENT_AUTH_GUARD_PATTERNS) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        // Find the line number.
        const upToMatch = file.content.slice(0, match.index);
        const lineNum = upToMatch.split('\n').length;

        findings.push({
          ruleId: 'client-only-auth',
          ruleName: 'Client-Only Auth Guards',
          severity: severity || 'warning',
          message: label,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: `Client-side auth only hides UI elements — it does NOT protect data. Always verify auth server-side in your API routes/middleware too. Anyone can open DevTools Console and call fetch("/your/api/endpoint") directly.`,
        });
      }
    }

    return findings;
  },
};
