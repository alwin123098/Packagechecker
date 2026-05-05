# Agent Firewall

Agent Firewall is a local CLI security gate for dependencies, install commands, and CI workflows. It is built with zero runtime dependencies so the scanner does not add another supply-chain risk to the project it protects.

## Install

From this folder:

```sh
npm link
```

Or run directly:

```sh
node ./bin/agent-firewall.js scan .
```

## Use

Scan a project:

```sh
agent-firewall scan .
```

Block CI on high risk:

```sh
agent-firewall scan . --fail-on high
```

Write a Markdown report:

```sh
agent-firewall scan . --markdown security-report.md
```

Write a SARIF report for GitHub code scanning:

```sh
agent-firewall scan . --sarif agent-firewall.sarif
```

Guard an install command:

```sh
agent-firewall guard -- npm install some-package
agent-firewall guard -- pip install -r requirements.txt
```

Create a policy file:

```sh
agent-firewall init .
```

## What It Checks

- npm and Python manifests
- lockfiles
- GitHub Actions workflows
- secrets in common config and source files
- lifecycle install scripts
- suspicious shell commands
- broad CI token permissions
- unpinned GitHub Actions
- typosquatting against popular packages
- obfuscated source that mixes encoded blobs with dynamic execution
- policy allowlists and blocklists

## Policy

`.agent-firewall.json`:

```json
{
  "failOn": "high",
  "exclude": ["test-fixtures/"],
  "allowedPackages": [],
  "blockedPackages": ["leftpad"],
  "allowedCommands": [],
  "blockedCommands": ["curl | sh"]
}
```

Exit code `2` means the scan or guard was blocked by policy.
