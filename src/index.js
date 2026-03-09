import { discoverFiles } from './scanner.js';
import { resolveRules } from './rules/index.js';
import { report } from './reporter.js';
import { loadConfig } from './config.js';

/**
 * Run the full audit pipeline.
 *
 * @param {string} targetDir - Absolute path to project root
 * @param {Object} [cliOptions] - Options from CLI flags (override config)
 * @param {string} [cliOptions.format]
 * @param {string[]} [cliOptions.rules]
 * @param {string[]} [cliOptions.exclude]
 * @param {boolean} [cliOptions.strict]
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

  // Resolve which rules to run.
  const rules = resolveRules(ruleIds, excludeIds);

  // Scan files and run rules.
  /** @type {import('./rules/types.js').Finding[]} */
  const findings = [];
  let filesScanned = 0;

  for await (const file of discoverFiles(targetDir, config.ignore)) {
    filesScanned++;
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

  const durationMs = Math.round(performance.now() - start);

  // Sort: criticals first, then warnings, then info.
  const severityOrder = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Report.
  report(findings, format, {
    filesScanned,
    rulesRun: rules.length,
    durationMs,
  });

  // Exit code: 1 if criticals found, 1 if warnings + strict mode, 0 otherwise.
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasWarning = findings.some((f) => f.severity === 'warning');
  const exitCode = hasCritical ? 1 : strict && hasWarning ? 1 : 0;

  return { findings, exitCode };
}
