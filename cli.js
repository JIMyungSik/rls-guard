#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';
import { scanSql } from './scanner.js';

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function usage() {
  return `RLS Guard 0.5.0

Usage:
  node cli.js [options] <migration.sql> [...more.sql]
  cat migration.sql | node cli.js [options]

Options:
  --fail-on <severity>  Exit 1 when this severity or higher is found
                        (critical, high, medium, low; default: critical)
  --format <type>       Report format: text, json, markdown (default: text)
  --json                Alias for --format json
  --output <path>       Write the report to a file instead of stdout
  --help                Show this help
`;
}

function parseArgs(argv) {
  const options = { files: [], failOn: 'critical', format: 'text', output: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { ...options, help: true };
    if (arg === '--json') { options.format = 'json'; continue; }
    if (arg === '--format') {
      const format = argv[i + 1]?.toLowerCase();
      if (!['text', 'json', 'markdown'].includes(format)) throw new Error('--format must be text, json, or markdown');
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
  if (options.files.length) {
    const contents = await Promise.all(options.files.map((file) => readFile(file, 'utf8')));
    sql = contents.map((content, index) => `\n-- file: ${options.files[index]}\n${content}`).join('\n');
    source = options.files.join(', ');
  } else if (!process.stdin.isTTY) {
    sql = await readStdin();
    source = 'stdin';
  } else {
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  const report = scanSql(sql, source);
  const rendered = options.format === 'json'
    ? JSON.stringify(report, null, 2)
    : options.format === 'markdown'
      ? markdownReport(report)
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
