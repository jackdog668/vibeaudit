/**
 * Rule: no-input-validation
 * Detects patterns where user input is used without validation or sanitization.
 * XSS and injection are the bread and butter of vibe-code vulnerabilities.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Patterns that indicate dangerous direct use of user input. */
const DANGEROUS_PATTERNS = [
  // dangerouslySetInnerHTML with user data
  {
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    label: 'dangerouslySetInnerHTML — potential XSS vector',
    severity: 'critical',
  },
  // innerHTML assignment
  {
    regex: /\.innerHTML\s*=\s*(?!['"`]\s*$)/g,
    label: 'Direct innerHTML assignment — potential XSS vector',
    severity: 'critical',
  },
  // document.write
  {
    regex: /document\.write\s*\(/g,
    label: 'document.write — XSS vector, avoid entirely',
    severity: 'critical',
  },
  // eval with variables
  {
    regex: /\beval\s*\(\s*[^)'"\s]/g,
    label: 'eval() with dynamic input — code injection risk',
    severity: 'critical',
  },
  // new Function with dynamic content
  {
    regex: /new\s+Function\s*\(\s*[^)'"\s]/g,
    label: 'new Function() with dynamic input — code injection risk',
    severity: 'critical',
  },
  // SQL query built with string concatenation/template literals
  {
    regex: /(?:query|execute|sql)\s*\(\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*\$\{/gi,
    label: 'SQL query built with string interpolation — SQL injection risk',
    severity: 'critical',
  },
  // Unparameterized query with concatenation
  {
    regex: /(?:query|execute)\s*\(\s*['"`].*\+\s*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    label: 'SQL query with string concatenation from user input',
    severity: 'critical',
  },
  // Shell exec with user input
  {
    regex: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:[`'"].*\$\{|.*\+\s*(?:req\.|request\.|params\.))/gi,
    label: 'Shell command with user input — command injection risk',
    severity: 'critical',
  },
  // Unvalidated redirect
  {
    regex: /(?:res\.redirect|window\.location|location\.href)\s*[=(]\s*(?:req\.|request\.|params\.|query\.|searchParams)/gi,
    label: 'Redirect using unvalidated user input — open redirect risk',
    severity: 'warning',
  },
];

/** @type {Rule} */
export const noInputValidation = {
  id: 'no-input-validation',
  name: 'No Input Validation',
  severity: 'critical',
  description: 'Detects patterns where user input is used unsafely without validation or sanitization.',

  check(file) {
    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];

      // Skip comments.
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      for (const { regex, label, severity } of DANGEROUS_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'no-input-validation',
            ruleName: 'No Input Validation',
            severity,
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Sanitize all user input before use. For HTML: use a sanitization library or textContent instead of innerHTML. For SQL: use parameterized queries. For shell: use allowlists, never interpolate user input into commands.`,
          });
        }
      }
    }

    return findings;
  },
};
