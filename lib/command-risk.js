export function assessCommand(parts, policy) {
  const command = parts.join(" ");
  const findings = [];
  const allowed = policy.allowedCommands?.some((item) => command.startsWith(item));
  if (allowed) return { findings };

  for (const blocked of policy.blockedCommands || []) {
    if (command.includes(blocked)) {
      findings.push({
        severity: "critical",
        rule: "blocked-command",
        location: "command",
        message: `Command matches blocked policy pattern: ${blocked}`,
        remediation: "Remove the command or add a narrower reviewed allowlist entry."
      });
    }
  }

  if (/\b(rm\s+-rf|mkfs|dd\s+if=|chmod\s+-R\s+777|chown\s+-R)\b/.test(command)) {
    findings.push({
      severity: "critical",
      rule: "destructive-shell-command",
      location: "command",
      message: "Command can destroy files, disks, or permissions recursively.",
      remediation: "Run only after manual review and a backup."
    });
  }

  if (/(curl|wget)\b.+\|\s*(sh|bash|python|node)\b/.test(command)) {
    findings.push({
      severity: "critical",
      rule: "remote-code-pipe",
      location: "command",
      message: "Command downloads remote code and executes it immediately.",
      remediation: "Download to a file, verify checksum/signature, then execute explicitly."
    });
  }

  if (/\b(npm|pnpm|yarn|pip|pip3|uv)\s+install\b/.test(command)) {
    findings.push({
      severity: "medium",
      rule: "dependency-install",
      location: "command",
      message: "Dependency install detected. Project manifests and policy were scanned before execution.",
      remediation: "Pin versions and keep lockfiles committed."
    });
  }

  if (/\b(sudo|su)\b/.test(command)) {
    findings.push({
      severity: "high",
      rule: "privileged-command",
      location: "command",
      message: "Command requests elevated privileges.",
      remediation: "Avoid privileged installs from untrusted projects."
    });
  }

  return { findings };
}
