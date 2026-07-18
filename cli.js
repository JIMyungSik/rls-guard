#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';
import { RULE_IDS, scanSql } from './scanner.js';

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SEVERITY_PENALTY = { critical: 30, high: 18, medium: 8, low: 3 };

function usage() {
  return `RLS Guard 0.7.0

Usage:
  node cli.js [options] <migration.sql> [...more.sql]
  cat migration.sql | node cli.js [options]

Options:
  --fail-on <severity>  Exit 1 when this severity or higher is found
                        (critical, high, medium, low; default: critical)
  --format <type>       Report format: text, json, markdown, sarif (default: text)
  --json                Alias for --format json
  --output <path>       Write the report to a file instead of stdout
  --ignore-rule <id>    Exclude a reviewed rule from reports and the exit code
                        Repeat for multiple rules (example: --ignore-rule RLS-002)
  --help                Show this help
`;
}

function parseArgs(argv) {
  const options = { files: [], failOn: 'critical', format: 'text', output: null, ignoredRules: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { ...options, help: true };
    if (arg === '--json') { options.format = 'json'; continue; }
    if (arg === '--format') {
      const format = argv[i + 1]?.toLowerCase();
      if (!['text', 'json', 'markdown', 'sarif'].includes(format)) throw new Error('--format must be text, json, markdown, or sarif');
      options.format = format;
      i += 1;
      continue;
    }
    if (arg === '--output') {
      const output = argv[i + 1];
      if (!output || output.startsWith('-')) throw new Error('--output requires a file path');
      options.output = output;
      i += 1;
      continue;
    }
    if (arg === '--fail-on') {
      const severity = argv[i + 1]?.toLowerCase();
      if (!SEVERITY_RANK[severity]) throw new Error('--fail-on must be critical, high, medium, or low');
      options.failOn = severity;
      i += 1;
      continue;
    }
    if (arg === '--ignore-rule') {
      const ruleId = argv[i + 1]?.toUpperCase();
      if (!RULE_IDS.includes(ruleId)) throw new Error(`--ignore-rule must be one of: ${RULE_IDS.join(', ')}`);
      if (!options.ignoredRules.includes(ruleId)) options.ignoredRules.push(ruleId);
      i += 1;
      continue;
    }
    if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    options.files.push(arg);
  }
  return options;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function textReport(report) {
  const lines = [
    `RLS Guard ${report.version} — score ${report.score}/100`,
    `Scanned ${report.summary.tables} table(s), ${report.summary.policies} policy/policies`,
    `Critical ${report.summary.critical} · High ${report.summary.high} · Medium ${report.summary.medium} · Low ${report.summary.low}`
  ];
  if (report.ignoredRules?.length) lines.push(`Ignored ${report.summary.ignored} finding(s) from reviewed rule(s): ${report.ignoredRules.join(', ')}`);
  for (const finding of report.findings) {
    lines.push('', `[${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.title}`, `  ${finding.target}`, `  Fix: ${finding.remediation}`);
  }
  if (!report.findings.length) lines.push('', 'No rule-based risks found. This is not a complete security audit.');
  return lines.join('\n');
}

function markdownCell(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', '<br>');
}

export function markdownReport(report) {
  const generated = new Date(report.scannedAt).toISOString();
  const lines = [
    '# RLS Guard Security Report',
    '',
    `- **Score:** ${report.score}/100`,
    `- **Source:** ${markdownCell(report.source)}`,
    `- **Generated:** ${generated}`,
    `- **RLS Guard:** ${report.version}`,
    ...(report.ignoredRules?.length ? [`- **Ignored reviewed rules:** ${report.ignoredRules.join(', ')} (${report.summary.ignored} finding(s))`] : []),
    '',
    '## Summary',
    '',
    '| Critical | High | Medium | Low | Tables | Policies |',
    '|---:|---:|---:|---:|---:|---:|',
    `| ${report.summary.critical} | ${report.summary.high} | ${report.summary.medium} | ${report.summary.low} | ${report.summary.tables} | ${report.summary.policies} |`
  ];
  if (!report.findings.length) {
    lines.push('', '## Findings', '', 'No rule-based risks found. **This is not a complete security audit.**');
  } else {
    lines.push('', '## Findings');
    report.findings.forEach((finding, index) => {
      lines.push(
        '',
        `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.ruleId} - ${finding.title}`,
        '',
        `- **Target:** ${markdownCell(finding.target)}`,
        `- **Confidence:** ${markdownCell(finding.confidence)}`,
        `- **Evidence:** ${markdownCell(finding.evidence)}`,
        '',
        '**Suggested remediation**',
        '',
        '```sql',
        finding.remediation,
        '```',
        '',
        '- [ ] Reviewed',
        '- [ ] Fixed',
        '- [ ] Verified with role-based tests'
      );
    });
  }
  lines.push('', '---', '', '> Static analysis only. Verify behavior with real roles and project-specific tests before production.', '');
  return lines.join('\n');
}

function applyIgnoredRules(report, ignoredRules) {
  if (!ignoredRules.length) return report;
  const ignored = new Set(ignoredRules);
  const findings = report.findings.filter((finding) => !ignored.has(finding.ruleId));
  const ignoredCount = report.findings.length - findings.length;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  const penalty = findings.reduce((sum, finding) => sum + SEVERITY_PENALTY[finding.severity], 0);
  return {
    ...report,
    score: Math.max(0, 100 - penalty),
    summary: { ...report.summary, ...counts, ignored: ignoredCount },
    findings,
    ignoredRules
  };
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

export function sarifReport(report) {
  const rules = [...new Map(report.findings.map((finding) => [finding.ruleId, {
    id: finding.ruleId,
    name: finding.ruleId.replace('-', '_'),
    shortDescription: { text: finding.title },
    help: { text: `${finding.evidence}\n\nSuggested remediation: ${finding.remediation}` },
    defaultConfiguration: { level: SARIF_LEVEL[finding.severity] }
  }])).values()];
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'RLS Guard', version: report.version, informationUri: 'https://rls-guard-rose.vercel.app', rules } },
      results: report.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: SARIF_LEVEL[finding.severity],
        message: { text: `${finding.title} Target: ${finding.target}. ${finding.evidence}` },
        ...(finding.location?.uri ? {
          locations: [{ physicalLocation: {
            artifactLocation: { uri: finding.location.uri.replaceAll('\\', '/') },
            region: { startLine: finding.location.startLine }
          } }]
        } : {}),
        properties: { severity: finding.severity, confidence: finding.confidence, remediation: finding.remediation }
      })),
      invocations: [{
        executionSuccessful: true,
        ...(report.ignoredRules?.length ? { properties: {
          ignoredRules: report.ignoredRules,
          ignoredFindingCount: report.summary.ignored
        } } : {})
      }]
    }]
  };
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`Error: ${error.message}\n\n${usage()}`);
    process.exitCode = 2;
    return;
  }
  if (options.help) { console.log(usage()); return; }

  let sql;
  let source;
  let sourceRanges = [];
  if (options.files.length) {
    const contents = await Promise.all(options.files.map((file) => readFile(file, 'utf8')));
    let nextLine = 1;
    const fragments = contents.map((content, index) => {
      const contentLines = content.split('\n').length;
      const range = { uri: options.files[index], startLine: nextLine + 1, endLine: nextLine + contentLines };
      sourceRanges.push(range);
      nextLine = range.endLine + 1;
      return `-- file: ${options.files[index]}\n${content}`;
    });
    sql = fragments.join('\n');
    source = options.files.join(', ');
  } else if (!process.stdin.isTTY) {
    sql = await readStdin();
    source = 'stdin';
  } else {
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  let report = scanSql(sql, source);
  if (sourceRanges.length) {
    report.findings = report.findings.map((finding) => {
      const combinedLine = finding.location?.startLine;
      const range = sourceRanges.find((item) => combinedLine >= item.startLine && combinedLine <= item.endLine);
      return range ? { ...finding, location: { uri: range.uri, startLine: combinedLine - range.startLine + 1 } } : finding;
    });
  }
  report = applyIgnoredRules(report, options.ignoredRules);
  const rendered = options.format === 'json'
    ? JSON.stringify(report, null, 2)
    : options.format === 'markdown'
      ? markdownReport(report)
      : options.format === 'sarif'
        ? JSON.stringify(sarifReport(report), null, 2)
      : textReport(report);
  if (options.output) await writeFile(options.output, `${rendered}\n`, 'utf8');
  else console.log(rendered);
  const threshold = SEVERITY_RANK[options.failOn];
  if (report.findings.some((finding) => SEVERITY_RANK[finding.severity] >= threshold)) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exitCode = 2;
});
