/**
 * Rule registry.
 * Each rule exports: { id, name, severity, description, check(file) }
 * check() returns an array of findings.
 */

import { exposedSecrets } from './exposed-secrets.js';
import { hardcodedCredentials } from './hardcoded-credentials.js';
import { exposedEnvVars } from './exposed-env-vars.js';
import { openDatabaseRules } from './open-database-rules.js';
import { missingAuth } from './missing-auth.js';
import { noInputValidation } from './no-input-validation.js';
import { insecureErrorHandling } from './insecure-error-handling.js';
import { missingSecurityHeaders } from './missing-security-headers.js';
import { missingRateLimiting } from './missing-rate-limiting.js';
import { insecureConnections } from './insecure-connections.js';
// DevTools exposure rules
import { clientBundleSecrets } from './client-bundle-secrets.js';
import { clientOnlyAuth } from './client-only-auth.js';
import { sensitiveBrowserStorage } from './sensitive-browser-storage.js';
import { consoleDataLeak } from './console-data-leak.js';
import { sourceMapsExposed } from './source-maps-exposed.js';
import { clientSideTrust } from './client-side-trust.js';
import { apiDataOverfetch } from './api-data-overfetch.js';
// Vibe coder blindspot rules
import { idorVulnerability } from './idor-vulnerability.js';
import { missingCsrf } from './missing-csrf.js';
import { unsafeFileUpload } from './unsafe-file-upload.js';
import { massAssignment } from './mass-assignment.js';
import { unverifiedWebhook } from './unverified-webhook.js';
import { noPagination } from './no-pagination.js';
// Advanced blindspot rules
import { pathTraversal } from './path-traversal.js';
import { insecureJwt } from './insecure-jwt.js';
import { plaintextPasswords } from './plaintext-passwords.js';
import { insecureRandomness } from './insecure-randomness.js';
import { insecureCookies } from './insecure-cookies.js';
import { ssrfVulnerability } from './ssrf-vulnerability.js';
import { prototypePollution } from './prototype-pollution.js';
import { missingGitignore } from './missing-gitignore.js';
import { timingAttack } from './timing-attack.js';
import { corsCredentials } from './cors-credentials.js';
import { noAccountLockout } from './no-account-lockout.js';
import { unsafeRedirect } from './unsafe-redirect.js';
// Bot/agent attack rules
import { noBotProtection } from './no-bot-protection.js';
import { predictableIds } from './predictable-ids.js';
import { debugModeExposed } from './debug-mode-exposed.js';
import { secretsInUrls } from './secrets-in-urls.js';

/** @type {import('./types.js').Rule[]} */
export const ALL_RULES = [
  // Core security
  exposedSecrets,
  hardcodedCredentials,
  exposedEnvVars,
  openDatabaseRules,
  missingAuth,
  noInputValidation,
  insecureErrorHandling,
  missingSecurityHeaders,
  missingRateLimiting,
  insecureConnections,
  // DevTools exposure
  clientBundleSecrets,
  clientOnlyAuth,
  sensitiveBrowserStorage,
  consoleDataLeak,
  sourceMapsExposed,
  clientSideTrust,
  apiDataOverfetch,
  // Vibe coder blindspots
  idorVulnerability,
  missingCsrf,
  unsafeFileUpload,
  massAssignment,
  unverifiedWebhook,
  noPagination,
  // Advanced blindspots
  pathTraversal,
  insecureJwt,
  plaintextPasswords,
  insecureRandomness,
  insecureCookies,
  ssrfVulnerability,
  prototypePollution,
  missingGitignore,
  timingAttack,
  corsCredentials,
  noAccountLockout,
  unsafeRedirect,
  // Bot/agent attacks
  noBotProtection,
  predictableIds,
  debugModeExposed,
  secretsInUrls,
];

/**
 * @param {string[]} ruleIds - IDs of rules to include (empty = all)
 * @param {string[]} excludeIds - IDs of rules to exclude
 * @returns {import('./types.js').Rule[]}
 */
export function resolveRules(ruleIds = [], excludeIds = []) {
  const excludeSet = new Set(excludeIds);
  let rules = ALL_RULES.filter((r) => !excludeSet.has(r.id));

  if (ruleIds.length > 0) {
    const includeSet = new Set(ruleIds);
    rules = rules.filter((r) => includeSet.has(r.id));
  }

  return rules;
}
