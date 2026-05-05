const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityRank(severity = "info") {
  return order[String(severity).toLowerCase()] ?? 0;
}

export function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  const top = findings.reduce((max, finding) => Math.max(max, severityRank(finding.severity)), 0);
  const risk = Object.entries(order).find(([, rank]) => rank === top)?.[0] || "info";
  return { counts, risk };
}

export function toJsonReport(report) {
  return report;
}

export function toMarkdownReport(report) {
  const lines = [
    "# Agent Firewall Report",
    "",
    `Target: \`${report.target}\``,
    `Risk: **${report.summary.risk.toUpperCase()}**`,
    "",
    "| Severity | Rule | Location | Message |",
    "| --- | --- | --- | --- |"
  ];
  for (const finding of report.findings) {
    lines.push(`| ${finding.severity} | ${finding.rule} | ${finding.location || "-"} | ${finding.message.replaceAll("|", "\\|")} |`);
  }
  if (!report.findings.length) lines.push("| info | clean | - | No risky patterns found. |");
  return `${lines.join("\n")}\n`;
}

export function toSarifReport(report) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "agent-firewall",
            informationUri: "https://example.invalid/agent-firewall",
            rules: [...new Set(report.findings.map((finding) => finding.rule))].map((rule) => ({
              id: rule,
              shortDescription: { text: rule }
            }))
          }
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.rule,
          level: finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "note",
          message: { text: finding.message },
          locations: finding.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: finding.location }
                  }
                }
              ]
            : []
        }))
      }
    ]
  };
}

export function printReport(report) {
  const { counts, risk } = report.summary;
  console.log(`\nAgent Firewall Report`);
  console.log(`Target: ${report.target}`);
  if (report.summary.command) console.log(`Command: ${report.summary.command}`);
  console.log(`Risk: ${risk.toUpperCase()}`);
  console.log(
    `Findings: critical=${counts.critical || 0} high=${counts.high || 0} medium=${counts.medium || 0} low=${counts.low || 0}`
  );

  if (!report.findings.length) {
    console.log("\nNo risky patterns found.");
    return;
  }

  console.log("");
  for (const finding of report.findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))) {
    console.log(`[${finding.severity.toUpperCase()}] ${finding.rule}`);
    console.log(`  ${finding.message}`);
    if (finding.location) console.log(`  at ${finding.location}`);
    if (finding.remediation) console.log(`  fix: ${finding.remediation}`);
  }
}
