/**
 * Rule: hardcoded-ip
 * Detects hardcoded IP addresses that should be in environment variables.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.d\.ts$|\.lock$)/i;
const SKIP_RULES = /src\/rules\//i;

// Match IPv4 addresses in strings (not localhost or common test IPs)
const IP_IN_STRING = /['"`](?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?['"`]/g;

// IPs to ignore (localhost, test ranges)
const IGNORE_IPS = /^(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)$/;

/** @type {Rule} */
export const hardcodedIp = {
  id: 'hardcoded-ip',
  name: 'Hardcoded IP Address',
  severity: 'info',
  description: 'Detects hardcoded IP addresses that should be in environment variables.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];

    const findings = [];

    IP_IN_STRING.lastIndex = 0;
    let match;
    while ((match = IP_IN_STRING.exec(file.content)) !== null) {
      const ip = match[1];
      if (IGNORE_IPS.test(ip)) continue;

      const lineNum = file.content.slice(0, match.index).split('\n').length;
      const line = file.lines[lineNum - 1]?.trim();
      if (line?.startsWith('//') || line?.startsWith('*') || line?.startsWith('#')) continue;

      findings.push({
        ruleId: 'hardcoded-ip',
        ruleName: 'Hardcoded IP Address',
        severity: 'info',
        message: `Hardcoded IP address ${ip} — should be in an environment variable.`,
        file: file.relativePath,
        line: lineNum,
        evidence: line?.slice(0, 120),
        fix: 'Move the IP address to an environment variable: process.env.SERVICE_HOST. Hardcoded IPs make deployment inflexible and may expose infrastructure details.',
      });
    }

    return findings;
  },
};
