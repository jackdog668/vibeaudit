import { discoverFiles } from './scanner.js';
import { resolveRules } from './rules/index.js';
import { report } from './reporter.js';
import { loadConfig } from './config.js';
import { CWE_MAP } from './data/cwe-map.js';
import { runSCA } from './sca/index.js';

/**
 * Run the full audit pipeline.
 *
 * @param {string} targetDir - Absolute path to project root
 * @param {Object} [cliOptions] - Options from CLI flags (override config)
 * @param {string} [cliOptions.format]
 * @param {string[]} [cliOptions.rules]
 * @param {string[]} [cliOptions.exclude]
 * @param {boolean} [cliOptions.strict]
 * @param {boolean} [cliOptions.skipSca]
 * @param {boolean} [cliOptions.deep]
 * @returns {Promise<{ findings: import('./rules/types.js').Finding[], exitCode: number }>}
 */
export async function audit(targetDir, cliOptions = {}) {
  const start = performance.now();

  // Load config, CLI flags override file config.
  const config = await loadConfig(targetDir);
  const format = cliOptions.format || config.format;
  const ruleIds = cliOptions.rules?.length ? cliOptions.rules : config.rules;
  const excludeIds = cliOptions.exclude?.length ? cliOptions.exclude : config.exclude;
  const strict = cliOptions.strict ?? config.strict;
  const skipSca = cliOptions.skipSca ?? false;
  const deep = cliOptions.deep ?? false;

  // Resolve which rules to run.
  const rules = resolveRules(ruleIds, excludeIds);

  // Scan files and run rules.
  /** @type {import('./rules/types.js').Finding[]} */
  const findings = [];
  let filesScanned = 0;

  for await (const file of discoverFiles(targetDir, config.ignore)) {
    filesScanned++;
    // Pass deep mode flag to rules that need it
    if (deep) file._deepMode = true;
    for (const rule of rules) {
      try {
        const ruleFindings = rule.check(file);
        findings.push(...ruleFindings);
      } catch {
        // A rule should never crash the entire audit.
        // Silently skip — the rule has a bug, not the user's code.
      }
    }
  }

  // SCA: Dependency vulnerability scanning.
  if (!skipSca) {
    try {
      const scaFindings = await runSCA(targetDir);
      findings.push(...scaFindings);
    } catch {
      // SCA failure should not crash the audit.
    }
  }

  const durationMs = Math.round(performance.now() - start);

  // Enrich findings with CWE/CVSS/OWASP metadata.
  for (const f of findings) {
    const meta = CWE_MAP[f.ruleId];
    if (meta) {
      f.cweId = meta.cweId;
      f.cvssScore = meta.cvssScore;
      f.owaspCategory = meta.owaspCategory;
    }
  }

  // Sort: criticals first, then warnings, then info.
  const severityOrder = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Report.
  await report(findings, format, {
    filesScanned,
    rulesRun: rules.length,
    durationMs,
    targetDir,
  });

  // Exit code: 1 if criticals found, 1 if warnings + strict mode, 0 otherwise.
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasWarning = findings.some((f) => f.severity === 'warning');
  const exitCode = hasCritical ? 1 : strict && hasWarning ? 1 : 0;

  return { findings, exitCode };
}
