/**
 * Rule: high-entropy-strings
 * Detects high-entropy strings in variable assignments that may be secrets.
 * Uses Shannon entropy to find potential hardcoded secrets that don't match
 * known patterns.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.d\.ts$|\.lock$|\.min\.js$)/i;
const SKIP_RULES = /src\/rules\//i;

/** Files where high-entropy strings are expected */
const IGNORE_FILES = /\.(?:env\.example|env\.sample|svg|png|jpg|ico|woff|css)$/i;

/** Variable names that suggest a secret */
const SECRET_VAR = /(?:key|secret|token|password|credential|api_key|apiKey|auth|private|signing|encryption)/i;

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy = more random = more likely a secret.
 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Match string assignments: const KEY = "value" or key: "value"
const STRING_ASSIGN = /(?:(?:const|let|var|export)\s+)?(\w+)\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{16,})['"](?:\s*[;,]|\s*$)/g;

/** @type {Rule} */
export const highEntropyStrings = {
  id: 'high-entropy-strings',
  name: 'High Entropy Strings',
  severity: 'warning',
  description: 'Detects high-entropy strings that may be hardcoded secrets.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];
    if (IGNORE_FILES.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      STRING_ASSIGN.lastIndex = 0;
      let match;
      while ((match = STRING_ASSIGN.exec(line)) !== null) {
        const varName = match[1];
        const value = match[2];

        // Only check variables that look like secrets
        if (!SECRET_VAR.test(varName)) continue;

        // Skip short values and common non-secrets
        if (value.length < 16 || value.length > 500) continue;

        const entropy = shannonEntropy(value);
        // Threshold: hex strings > 4.0, base64 > 4.5
        const isHex = /^[0-9a-fA-F]+$/.test(value);
        const threshold = isHex ? 3.5 : 4.0;

        if (entropy > threshold) {
          findings.push({
            ruleId: 'high-entropy-strings',
            ruleName: 'High Entropy Strings',
            severity: 'warning',
            message: `Variable "${varName}" contains a high-entropy string (entropy: ${entropy.toFixed(1)}) — possible hardcoded secret.`,
            file: file.relativePath,
            line: i + 1,
            evidence: `${varName} = "${value.slice(0, 4)}...(redacted)...${value.slice(-4)}"`,
            fix: 'Move this value to an environment variable. If it\'s a secret, add it to .env (git-ignored) and reference via process.env.',
          });
        }
      }
    }

    return findings;
  },
};
