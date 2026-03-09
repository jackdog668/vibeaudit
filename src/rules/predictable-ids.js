/**
 * Rule: predictable-ids
 * Detects auto-incrementing or sequential IDs exposed in URLs/APIs.
 *
 * The attack: /api/invoices/1001 exists, so try /api/invoices/1002, 1003...
 * Enumerate every invoice, user, order in your system. Know exactly how
 * many users you have. Scrape everything sequentially. Combined with
 * an IDOR bug, this is a full database dump.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SEQUENTIAL_ID_PATTERNS = [
  // Prisma autoincrement
  { regex: /id\s+Int\s+@id\s+@default\s*\(\s*autoincrement\s*\(\s*\)\s*\)/gi, label: 'Auto-incrementing integer ID — sequential and enumerable' },
  // MongoDB ObjectId is NOT sequential but close enough to time-order
  // Sequelize autoIncrement
  { regex: /autoIncrement\s*:\s*true/gi, label: 'Auto-incrementing ID — sequential and enumerable' },
  // Knex increments
  { regex: /\.increments\s*\(\s*['"`]id['"`]\s*\)/gi, label: 'Auto-incrementing ID column — sequential and enumerable' },
  // TypeORM PrimaryGeneratedColumn without uuid
  { regex: /@PrimaryGeneratedColumn\s*\(\s*\)/g, label: 'Auto-incrementing primary key — sequential and enumerable' },
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const predictableIds = {
  id: 'predictable-ids',
  name: 'Predictable IDs',
  severity: 'info',
  description: 'Detects auto-incrementing IDs exposed in APIs — enables enumeration attacks and reveals your total record count.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label } of SEQUENTIAL_ID_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'predictable-ids',
            ruleName: 'Predictable IDs',
            severity: 'info',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Use UUIDs (crypto.randomUUID()) or CUIDs instead of auto-incrementing integers for public-facing IDs. Sequential IDs let attackers enumerate every record by incrementing the number. Keep autoincrement for internal DB use but expose a random public ID.`,
          });
        }
      }
    }

    return findings;
  },
};
