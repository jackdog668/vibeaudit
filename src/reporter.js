import { bold, red, yellow, cyan, green, gray, dim, bgRed, bgYellow, bgGreen } from './colors.js';
import { getFixPrompt } from './data/prompts.js';

/**
 * @typedef {import('./rules/types.js').Finding} Finding
 */

/**
 * Format and print findings to stdout.
 *
 * @param {Finding[]} findings
 * @param {'terminal' | 'json' | 'markdown'} format
 * @param {{ filesScanned: number, rulesRun: number, durationMs: number }} meta
 */
export function report(findings, format, meta) {
  switch (format) {
    case 'json':
      return reportJSON(findings, meta);
    case 'markdown':
      return reportMarkdown(findings, meta);
    default:
      return reportTerminal(findings, meta);
  }
}

// ─── Terminal ─────────────────────────────────────────────────────────────────

function reportTerminal(findings, meta) {
  const criticals = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  const infos = findings.filter((f) => f.severity === 'info');

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT'));
  console.log(dim('  Security audit for AI-generated code'));
  console.log(dim(`  ─────────────────────────────────────`));
  console.log('');

  if (findings.length === 0) {
    console.log(green(bold('  ✅ No issues found.')));
    console.log('');
    printSummaryBar(criticals.length, warnings.length, infos.length, meta);
    return;
  }

  // Group findings by file.
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  for (const [file, fileFindings] of byFile) {
    console.log(bold(cyan(`  ${file}`)));

    for (const f of fileFindings) {
      const icon = severityIcon(f.severity);
      const lineStr = f.line ? gray(`:${f.line}`) : '';
      const cweStr = f.cweId ? dim(` [${f.cweId}]`) : '';
      console.log(`    ${icon}  ${f.message}${lineStr}${cweStr}`);
      if (f.evidence) {
        console.log(`        ${dim(f.evidence)}`);
      }
      console.log(`        ${dim('Fix:')} ${gray(f.fix)}`);
      console.log('');
    }
  }

  printSummaryBar(criticals.length, warnings.length, infos.length, meta);
}

function severityIcon(severity) {
  switch (severity) {
    case 'critical':
      return red('●');
    case 'warning':
      return yellow('▲');
    case 'info':
      return cyan('ℹ');
    default:
      return ' ';
  }
}

function printSummaryBar(critCount, warnCount, infoCount, meta) {
  const total = critCount + warnCount + infoCount;
  console.log(dim('  ─────────────────────────────────────'));

  const parts = [];
  if (critCount > 0) parts.push(red(bold(`${critCount} critical`)));
  if (warnCount > 0) parts.push(yellow(`${warnCount} warning${warnCount !== 1 ? 's' : ''}`));
  if (infoCount > 0) parts.push(cyan(`${infoCount} info`));
  if (total === 0) parts.push(green('0 issues'));

  console.log(`  ${parts.join(dim(' · '))}`);
  console.log(
    dim(
      `  ${meta.filesScanned} files scanned · ${meta.rulesRun} rules · ${meta.durationMs}ms`
    )
  );
  console.log('');

  if (critCount > 0) {
    console.log(red(bold('  ⛔ CRITICAL issues found. Fix these before deploying.')));
  } else if (warnCount > 0) {
    console.log(yellow(bold('  ⚠️  Warnings found. Review before going live.')));
  } else {
    console.log(green(bold('  ✅ Looking clean. Ship it.')));
  }
  console.log('');
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

function reportJSON(findings, meta) {
  // Enrich findings with fix prompts.
  const enriched = findings.map((f) => {
    const promptData = getFixPrompt(f.ruleId);
    const entry = { ...f };
    if (promptData) {
      entry.prompt = promptData.prompt;
      entry.platformNotes = promptData.platformNotes;
    }
    return entry;
  });

  const output = {
    summary: {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      warning: findings.filter((f) => f.severity === 'warning').length,
      info: findings.filter((f) => f.severity === 'info').length,
      filesScanned: meta.filesScanned,
      rulesRun: meta.rulesRun,
      durationMs: meta.durationMs,
    },
    findings: enriched,
  };

  console.log(JSON.stringify(output, null, 2));
}

// ─── Markdown ─────────────────────────────────────────────────────────────────

function reportMarkdown(findings, meta) {
  const criticals = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  const infos = findings.filter((f) => f.severity === 'info');

  const lines = [
    '# ⚗️ Vibe Audit Report',
    '',
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Files scanned | ${meta.filesScanned} |`,
    `| Rules run | ${meta.rulesRun} |`,
    `| Critical | ${criticals.length} |`,
    `| Warnings | ${warnings.length} |`,
    `| Info | ${infos.length} |`,
    `| Duration | ${meta.durationMs}ms |`,
    '',
  ];

  if (findings.length === 0) {
    lines.push('**✅ No issues found.**');
  } else {
    const renderFinding = (f) => {
      const cweBadge = f.cweId ? ` \`${f.cweId}\`` : '';
      lines.push(`### \`${f.file}\`${f.line ? `:${f.line}` : ''}${cweBadge}`);
      lines.push(`- **${f.message}**`);
      if (f.evidence) lines.push(`- Evidence: \`${f.evidence}\``);
      lines.push(`- Fix: ${f.fix}`);
      const promptData = getFixPrompt(f.ruleId);
      if (promptData) {
        lines.push('');
        lines.push('<details><summary>📋 Copy-paste fix prompt (works in any AI coding tool)</summary>');
        lines.push('');
        lines.push('```');
        lines.push(promptData.prompt);
        lines.push('```');
        if (promptData.platformNotes) {
          lines.push('');
          lines.push(`**Platform notes:** ${promptData.platformNotes}`);
        }
        lines.push('');
        lines.push('</details>');
      }
      lines.push('');
    };

    if (criticals.length > 0) {
      lines.push('## 🔴 Critical', '');
      for (const f of criticals) renderFinding(f);
    }

    if (warnings.length > 0) {
      lines.push('## 🟡 Warnings', '');
      for (const f of warnings) renderFinding(f);
    }

    if (infos.length > 0) {
      lines.push('## ℹ️ Info', '');
      for (const f of infos) {
        lines.push(`- \`${f.file}\`${f.line ? `:${f.line}` : ''} — ${f.message}`);
      }
      lines.push('');
    }
  }

  console.log(lines.join('\n'));
}
