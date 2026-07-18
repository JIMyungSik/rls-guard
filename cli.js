#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import process from 'node:process';
import { scanSql } from './scanner.js';

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function usage() {
  return `RLS Guard 0.2.1

Usage:
  node cli.js [options] <migration.sql> [...more.sql]
  cat migration.sql | node cli.js [options]

Options:
  --fail-on <severity>  Exit 1 when this severity or higher is found
                        (critical, high, medium, low; default: critical)
  --json                Print the complete JSON report
  --help                Show this help
`;
}

function parseArgs(argv) {
  const options = { files: [], failOn: 'critical', json: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { ...options, help: true };
    if (arg === '--json') { options.json = true; continue; }
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
  console.log(options.json ? JSON.stringify(report, null, 2) : textReport(report));
  const threshold = SEVERITY_RANK[options.failOn];
  if (report.findings.some((finding) => SEVERITY_RANK[finding.severity] >= threshold)) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exitCode = 2;
});
