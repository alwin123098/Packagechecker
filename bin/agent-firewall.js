#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { loadPolicy } from "../lib/policy.js";
import { scanProject } from "../lib/scanner.js";
import { assessCommand } from "../lib/command-risk.js";
import { printReport, toJsonReport, toMarkdownReport, toSarifReport, severityRank } from "../lib/report.js";

const args = process.argv.slice(2);
const command = args[0];

function usage() {
  console.log(`agent-firewall

Usage:
  agent-firewall scan [path] [--fail-on low|medium|high|critical] [--json] [--markdown file] [--sarif file]
  agent-firewall guard -- <command...>
  agent-firewall init [path]

Examples:
  agent-firewall scan .
  agent-firewall scan . --fail-on high --markdown security-report.md
  agent-firewall guard -- npm install leftpad
  agfw guard -- pip install -r requirements.txt
`);
}

function optionValue(flag, fallback = undefined) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : fallback;
}

function hasFlag(flag) {
  return args.includes(flag);
}

function failOnExit(report, failOn) {
  if (!failOn) return 0;
  const threshold = severityRank(failOn);
  return report.findings.some((finding) => severityRank(finding.severity) >= threshold) ? 2 : 0;
}

if (!command || command === "-h" || command === "--help") {
  usage();
  process.exit(0);
}

if (command === "init") {
  const target = resolve(args[1] || ".");
  const file = resolve(target, ".agent-firewall.json");
  if (existsSync(file)) {
    console.error(`Policy already exists: ${file}`);
    process.exit(1);
  }
  mkdirSync(target, { recursive: true });
  writeFileSync(
    file,
    JSON.stringify(
      {
        failOn: "high",
        allowedPackages: [],
        blockedPackages: [],
        allowedCommands: [],
        blockedCommands: ["rm -rf /", "curl | sh", "wget | sh"],
        trustedDomains: ["github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
      },
      null,
      2
    )
  );
  console.log(`Created ${file}`);
  process.exit(0);
}

if (command === "scan") {
  const targetArg = args[1] && !args[1].startsWith("--") ? args[1] : ".";
  const target = resolve(targetArg);
  const policy = loadPolicy(target);
  const report = scanProject(target, policy);
  const markdownPath = optionValue("--markdown");
  const sarifPath = optionValue("--sarif");

  if (markdownPath) {
    writeFileSync(resolve(markdownPath), toMarkdownReport(report));
  }
  if (sarifPath) {
    writeFileSync(resolve(sarifPath), JSON.stringify(toSarifReport(report), null, 2));
  }

  if (hasFlag("--json")) {
    console.log(JSON.stringify(toJsonReport(report), null, 2));
  } else {
    printReport(report);
    if (markdownPath) console.log(`\nMarkdown report: ${resolve(markdownPath)}`);
    if (sarifPath) console.log(`SARIF report: ${resolve(sarifPath)}`);
  }

  const failOn = optionValue("--fail-on", policy.failOn);
  process.exit(failOnExit(report, failOn));
}

if (command === "guard") {
  const separator = args.indexOf("--");
  const guardedCommand = separator >= 0 ? args.slice(separator + 1) : args.slice(1);
  if (!guardedCommand.length) {
    console.error("Missing command. Use: agent-firewall guard -- <command...>");
    process.exit(1);
  }

  const target = process.cwd();
  const policy = loadPolicy(target);
  const projectReport = scanProject(target, policy);
  const commandReport = assessCommand(guardedCommand, policy);
  const report = {
    ...projectReport,
    findings: [...commandReport.findings, ...projectReport.findings],
    summary: {
      ...projectReport.summary,
      command: guardedCommand.join(" ")
    }
  };

  printReport(report);
  const block = report.findings.some((finding) => severityRank(finding.severity) >= severityRank(policy.failOn || "high"));
  if (block) {
    console.error("\nBlocked by agent-firewall policy. Review findings or add an explicit allowlist entry.");
    process.exit(2);
  }

  const child = spawnSync(guardedCommand[0], guardedCommand.slice(1), {
    stdio: "inherit",
    shell: false
  });
  process.exit(child.status ?? 1);
}

console.error(`Unknown command: ${command}`);
usage();
process.exit(1);
