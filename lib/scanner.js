import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { summarize } from "./report.js";

const ignoredDirs = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".cache"]);
const maxFileBytes = 512 * 1024;

const popularPackages = [
  "react",
  "lodash",
  "axios",
  "express",
  "next",
  "typescript",
  "vite",
  "django",
  "flask",
  "requests",
  "numpy",
  "pandas",
  "pytest",
  "openai",
  "langchain",
  "fastapi"
];

const dangerousScriptTerms = [
  "curl ",
  "wget ",
  "Invoke-WebRequest",
  "base64",
  "eval(",
  "child_process",
  "powershell",
  "chmod +x",
  "nc ",
  "netcat",
  "/etc/passwd",
  ".ssh",
  "process.env"
];

const secretRules = [
  ["github-token", /gh[pousr]_[A-Za-z0-9_]{20,}/g],
  ["aws-access-key", /AKIA[0-9A-Z]{16}/g],
  ["google-api-key", /AIza[0-9A-Za-z_-]{20,}/g],
  ["openai-api-key", /sk-[A-Za-z0-9_-]{20,}/g],
  ["private-key", /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g],
  ["generic-secret-assignment", /\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*["'][^"']{12,}["']/gi]
];

function isExcluded(root, full, policy) {
  const rel = relative(root, full).replaceAll("\\", "/");
  return (policy.exclude || []).some((pattern) => {
    const clean = pattern.replaceAll("\\", "/").replace(/^\.\//, "");
    return rel === clean || rel.startsWith(clean.replace(/\/$/, "") + "/");
  });
}

function walk(root, policy, dir = root, files = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (ignoredDirs.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (isExcluded(root, full, policy)) continue;
    if (entry.isDirectory()) {
      walk(root, policy, full, files);
    } else if (entry.isFile()) {
      files.push(full);
    }
  }
  return files;
}

function readSmall(file) {
  try {
    if (statSync(file).size > maxFileBytes) return "";
    return readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

function location(root, file) {
  return relative(root, file) || basename(file);
}

function add(findings, severity, rule, file, message, remediation) {
  findings.push({
    severity,
    rule,
    location: file,
    message,
    remediation
  });
}

function levenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return matrix[a.length][b.length];
}

function isLikelyTypo(name, trusted) {
  const lowerName = name.toLowerCase();
  const lowerTrusted = trusted.toLowerCase();
  if (levenshtein(lowerName, lowerTrusted) === 1) return true;
  if (lowerName.length !== lowerTrusted.length) return false;
  for (let i = 0; i < lowerName.length - 1; i++) {
    const swapped = lowerName.slice(0, i) + lowerName[i + 1] + lowerName[i] + lowerName.slice(i + 2);
    if (swapped === lowerTrusted) return true;
  }
  return false;
}

function packageRisk(name, version, policy, file, findings) {
  if (policy.allowedPackages?.includes(name)) return;
  if (policy.blockedPackages?.includes(name)) {
    add(findings, "critical", "blocked-package", file, `${name} is blocked by policy.`, "Remove it or review the policy.");
  }

  if (/^(latest|\*|x)$/i.test(String(version)) || /[><]/.test(String(version))) {
    add(
      findings,
      "medium",
      "unpinned-version",
      file,
      `${name} uses a loose version range (${version}).`,
      "Pin exact versions in apps and commit lockfiles."
    );
  }

  for (const trusted of popularPackages) {
    if (name !== trusted && isLikelyTypo(name, trusted)) {
      add(
        findings,
        "high",
        "possible-typosquat",
        file,
        `${name} is one edit away from popular package ${trusted}.`,
        "Confirm this package is intentional before installing."
      );
    }
  }
}

function scanPackageJson(root, file, findings, policy) {
  try {
    const json = JSON.parse(readSmall(file));
    const rel = location(root, file);
    const deps = {
      ...(json.dependencies || {}),
      ...(json.devDependencies || {}),
      ...(json.optionalDependencies || {}),
      ...(json.peerDependencies || {})
    };
    for (const [name, version] of Object.entries(deps)) packageRisk(name, version, policy, rel, findings);

    for (const [script, value] of Object.entries(json.scripts || {})) {
      const text = String(value);
      if (/^(preinstall|install|postinstall|prepare)$/.test(script)) {
        add(
          findings,
          "high",
          "lifecycle-install-script",
          rel,
          `package.json defines ${script}: ${text}`,
          "Lifecycle scripts execute during installs. Keep them minimal and reviewed."
        );
      }
      for (const term of dangerousScriptTerms) {
        if (text.includes(term)) {
          add(findings, "high", "dangerous-npm-script", rel, `Script "${script}" contains risky term "${term.trim()}".`, "Review or remove the script.");
        }
      }
    }
  } catch (error) {
    add(findings, "low", "invalid-package-json", location(root, file), `Could not parse package.json: ${error.message}`, "Fix JSON syntax.");
  }
}

function scanPythonManifest(root, file, findings, policy) {
  const rel = location(root, file);
  const text = readSmall(file);
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const clean = line.trim();
    if (!clean || clean.startsWith("#") || clean.startsWith("[") || clean.includes("://")) continue;
    const match = clean.match(/^([A-Za-z0-9_.-]+)\s*([=<>!~]{1,2}.*)?$/);
    if (match) packageRisk(match[1], match[2] || "unbounded", policy, rel, findings);
  }

  if (/\bsetup_requires\b|\bdependency_links\b/.test(text)) {
    add(findings, "medium", "legacy-python-install-hook", rel, "Python manifest uses legacy dependency hooks.", "Prefer modern pyproject builds and pinned dependencies.");
  }
}

function scanLockfile(root, file, findings) {
  const rel = location(root, file);
  const text = readSmall(file);
  if (/(postinstall|preinstall|install)\b/.test(text) && /(http|base64|child_process|\.ssh|process\.env)/.test(text)) {
    add(findings, "high", "suspicious-lockfile-script", rel, "Lockfile references install scripts with network, env, or obfuscation indicators.", "Inspect the resolved package before installing.");
  }
  if (/resolved["']?\s*[:=]\s*["']http:\/\//.test(text)) {
    add(findings, "high", "insecure-registry-url", rel, "Lockfile contains an HTTP registry URL.", "Use HTTPS registries only.");
  }
}

function scanWorkflow(root, file, findings) {
  const rel = location(root, file);
  const text = readSmall(file);
  if (/permissions:\s*(write-all|\{[^}]*contents:\s*write)/i.test(text)) {
    add(findings, "high", "broad-github-token-permissions", rel, "GitHub Actions grants broad write permissions.", "Use least-privilege workflow permissions.");
  }
  if (/pull_request_target:/i.test(text)) {
    add(findings, "high", "pull-request-target", rel, "Workflow uses pull_request_target, which can expose privileged tokens to PR logic.", "Avoid it unless every checkout/script path is hardened.");
  }
  if (/(curl|wget).+\|\s*(sh|bash|python|node)/.test(text)) {
    add(findings, "critical", "ci-remote-code-pipe", rel, "CI executes downloaded code through a shell pipe.", "Pin installers and verify checksums/signatures.");
  }
  if (/uses:\s*[^@\s]+(\s|$)/.test(text) || /uses:\s*[^@\s]+@main\b/.test(text)) {
    add(findings, "medium", "unpinned-github-action", rel, "Workflow action is not pinned to an immutable commit.", "Pin actions to a full commit SHA for sensitive workflows.");
  }
}

function scanSecrets(root, file, findings) {
  const rel = location(root, file);
  const text = readSmall(file);
  if (!text) return;
  for (const [rule, regex] of secretRules) {
    const matches = text.match(regex);
    if (matches?.length) {
      add(findings, "critical", rule, rel, `Possible secret detected (${matches.length} match${matches.length === 1 ? "" : "es"}).`, "Rotate the secret and remove it from git history.");
    }
  }
}

function scanSourceForObfuscation(root, file, findings) {
  const rel = location(root, file);
  const text = readSmall(file);
  if (!text) return;
  const base64Hits = text.match(/[A-Za-z0-9+/]{120,}={0,2}/g) || [];
  if (base64Hits.length >= 2 && /(eval|Function|exec|spawn|subprocess|os\.system)/.test(text)) {
    add(findings, "high", "obfuscated-execution", rel, "Source contains long encoded blobs near dynamic execution.", "Review manually before running.");
  }
}

export function scanProject(target, policy) {
  const findings = [];
  if (policy.policyError) {
    add(findings, "high", "invalid-policy", ".agent-firewall.json", policy.policyError, "Fix or remove the policy file.");
  }

  if (!existsSync(target)) {
    add(findings, "critical", "missing-target", target, "Scan target does not exist.", "Use an existing project path.");
    return { target, findings, summary: summarize(findings) };
  }

  for (const file of walk(target, policy)) {
    const rel = location(target, file);
    const name = basename(file);
    if (name === "package.json") scanPackageJson(target, file, findings, policy);
    if (["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"].includes(name)) scanPythonManifest(target, file, findings, policy);
    if (["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"].includes(name)) scanLockfile(target, file, findings);
    if (rel.startsWith(".github/workflows/") && /\.(yml|yaml)$/.test(name)) scanWorkflow(target, file, findings);
    if (/\.(env|pem|key|json|yaml|yml|toml|ini|txt|js|ts|py)$/.test(name) || name.startsWith(".env")) scanSecrets(target, file, findings);
    if (/\.(js|mjs|cjs|ts|py|sh)$/.test(name)) scanSourceForObfuscation(target, file, findings);
  }

  return {
    target,
    findings,
    summary: summarize(findings)
  };
}
