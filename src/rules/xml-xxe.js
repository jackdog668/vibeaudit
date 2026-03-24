/**
 * Rule: xml-xxe
 * Detects XML parsing with external entities enabled (XXE attacks).
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

const XXE_PATTERNS = [
  // libxmljs with noent
  { pattern: /parseXml\s*\([\s\S]{0,200}noent\s*:\s*true/gi, label: 'XML parser with external entities enabled (noent: true)' },
  // xml2js without explicit entity disabling
  { pattern: /xml2js.*Parser|parseString/gi, label: 'xml2js parser (check entity handling config)' },
  // DOMParser on server with user input
  { pattern: /new\s+DOMParser\s*\(\s*\)[\s\S]{0,200}(?:req\.|request\.|body\.|input)/gi, label: 'DOMParser with user-provided XML' },
  // expat/sax without entity handling
  { pattern: /(?:require|import).*(?:node-expat|sax|fast-xml-parser)/gi, label: 'XML parser imported — ensure external entities are disabled' },
];

/** @type {Rule} */
export const xmlXxe = {
  id: 'xml-xxe',
  name: 'XML External Entity (XXE)',
  severity: 'critical',
  description: 'Detects XML parsing configurations vulnerable to XXE attacks.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/(?:xml|parseXml|DOMParser|xml2js|expat|sax)/i.test(file.content)) return [];

    const findings = [];

    for (const { pattern, label } of XXE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        const line = file.lines[lineNum - 1]?.trim();
        if (line?.startsWith('//') || line?.startsWith('*')) continue;

        findings.push({
          ruleId: 'xml-xxe',
          ruleName: 'XML External Entity (XXE)',
          severity: 'critical',
          message: `${label}.`,
          file: file.relativePath,
          line: lineNum,
          evidence: line?.slice(0, 120),
          fix: 'Disable external entity processing: for libxmljs use noent: false. For xml2js it is disabled by default. Avoid parsing untrusted XML when possible — use JSON instead.',
        });
      }
    }

    return findings;
  },
};
