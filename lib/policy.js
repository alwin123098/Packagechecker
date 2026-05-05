import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const defaults = {
  failOn: "high",
  allowedPackages: [],
  blockedPackages: [],
  allowedCommands: [],
  blockedCommands: [],
  exclude: [],
  trustedDomains: ["github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
};

export function loadPolicy(target) {
  const file = resolve(target, ".agent-firewall.json");
  if (!existsSync(file)) return defaults;
  try {
    return { ...defaults, ...JSON.parse(readFileSync(file, "utf8")) };
  } catch (error) {
    return {
      ...defaults,
      policyError: `Could not parse ${file}: ${error.message}`
    };
  }
}
