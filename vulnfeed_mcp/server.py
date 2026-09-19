"""VulnFeed MCP Server — vulnerability scanning for Claude Code.

Exposes tools:
  - scan_lockfile: parse a lockfile and report vulnerabilities
  - check_package: check a single package for known vulns
  - scan_project: auto-detect and scan lockfiles in a project directory
  - lookup_cve: detailed CVE lookup with EPSS + fix versions
  - monitor_project: register a project for continuous vulnerability monitoring
  - check_alerts: check for new vulnerabilities since last scan
  - list_monitored: list all monitored projects

The backend URL is baked in. Only VULNFEED_API_KEY is needed for paid
features; free tier works with no env vars at all.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

from mcp.server import FastMCP

DEFAULT_WORKER_URL = "https://vulnfeed-api.novadyne.ai"
WORKER_URL = os.environ.get("VULNFEED_WORKER_URL", os.environ.get("WORKER_URL", DEFAULT_WORKER_URL))
WORKER_KEY = os.environ.get("VULNFEED_API_KEY", os.environ.get("WORKER_BOOTSTRAP_KEY", ""))

LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements.in", "Pipfile.lock",
    "go.sum", "go.mod",
    "Cargo.lock", "Gemfile.lock", "composer.lock"
}

mcp = FastMCP(
    "VulnFeed",
    instructions=(
        "VulnFeed scans your project dependencies for known vulnerabilities "
        "and monitors them continuously. "
        "It reads lockfiles (package-lock.json, requirements.txt, go.sum), "
        "checks them against NVD, GitHub Advisories, and EPSS exploit data, "
        "and returns prioritized results with fix recommendations. "
        "Use scan_project for a one-time scan, or monitor_project to register "
        "for continuous monitoring — then check_alerts to see new vulns."
    ),
)


def _query_worker(packages: list[dict]) -> dict:
    all_results = []
    for i in range(0, len(packages), 500):
        batch = packages[i : i + 500]
        payload = json.dumps({"packages": batch}).encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "vulnfeed-mcp/0.3",
        }
        if WORKER_KEY:
            headers["Authorization"] = f"Bearer {WORKER_KEY}"
        req = urllib.request.Request(
            f"{WORKER_URL}/vulnscan/query",
            data=payload,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            return {"ok": False, "error": f"Backend HTTP {e.code}: {body}"}
        except Exception as e:
            return {"ok": False, "error": f"Backend unreachable: {e}"}

        if not data.get("ok"):
            return {"ok": False, "error": data.get("error", "unknown")}
        all_results.extend(data.get("results", []))

    return {"ok": True, "results": all_results}


# --- Lockfile parsers (mirrors scanner.py) ---

import re as _re


def _parse_package_lock(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    packages, seen = [], set()
    if "packages" in data:
        for key, info in data["packages"].items():
            if not key:
                continue
            name = info.get("name") or key.split("node_modules/")[-1]
            version = info.get("version")
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                packages.append({"name": name, "version": version, "ecosystem": "npm"})
    elif "dependencies" in data:
        def walk(deps):
            for name, info in deps.items():
                version = info.get("version")
                if name and version and (name, version) not in seen:
                    seen.add((name, version))
                    packages.append({"name": name, "version": version, "ecosystem": "npm"})
                if "dependencies" in info:
                    walk(info["dependencies"])
        walk(data["dependencies"])
    return packages


def _parse_requirements(path: str) -> list[dict]:
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", line)
            if m:
                packages.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "PyPI"})
    return packages


def _parse_go_sum(path: str) -> list[dict]:
    packages, seen = [], set()
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            name = parts[0]
            version = parts[1].split("/")[0].lstrip("v")
            if (name, version) not in seen:
                seen.add((name, version))
                packages.append({"name": name, "version": version, "ecosystem": "Go"})
    return packages


def _parse_yarn_lock(path: str) -> list[dict]:
    packages, seen = [], set()
    with open(path) as f:
        current_names = []
        for line in f:
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith(" ") and line.endswith(":"):
                current_names = []
                specs = line.rstrip(":").split(", ")
                for spec in specs:
                    spec = spec.strip().strip('"')
                    at = spec.rfind("@")
                    if at > 0:
                        current_names.append(spec[:at])
            elif line.strip().startswith("version "):
                version = line.strip().split('"')[1] if '"' in line else line.strip().split()[-1]
                for name in current_names:
                    if (name, version) not in seen:
                        seen.add((name, version))
                        packages.append({"name": name, "version": version, "ecosystem": "npm"})
                current_names = []
    return packages


def _parse_pipfile_lock(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    packages = []
    for section in ("default", "develop"):
        deps = data.get(section, {})
        for name, info in deps.items():
            version = info.get("version", "").lstrip("=")
            if name and version:
                packages.append({"name": name.lower(), "version": version, "ecosystem": "PyPI"})
    return packages


def _parse_cargo_lock(path: str) -> list[dict]:
    packages = []
    name, version = None, None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line == "[[package]]":
                if name and version:
                    packages.append({"name": name, "version": version, "ecosystem": "crates.io"})
                name, version = None, None
            elif line.startswith("name = "):
                name = line.split('"')[1] if '"' in line else None
            elif line.startswith("version = "):
                version = line.split('"')[1] if '"' in line else None
    if name and version:
        packages.append({"name": name, "version": version, "ecosystem": "crates.io"})
    return packages


def _parse_gemfile_lock(path: str) -> list[dict]:
    packages = []
    in_specs = False
    with open(path) as f:
        for line in f:
            stripped = line.rstrip()
            if stripped == "  specs:":
                in_specs = True
                continue
            if in_specs:
                if not stripped.startswith("    "):
                    in_specs = False
                    continue
                m = _re.match(r"^    (\S+) \((\S+)\)", stripped)
                if m:
                    packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": "RubyGems"})
    return packages


def _parse_composer_lock(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    packages = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name")
            version = (pkg.get("version") or "").lstrip("v")
            if name and version:
                packages.append({"name": name, "version": version, "ecosystem": "Packagist"})
    return packages


def _parse_pnpm_lock(path: str) -> list[dict]:
    packages, seen = [], set()
    with open(path) as f:
        for line in f:
            m = _re.match(r"^\s+['\"]?/?([^@\s][^@]*)@(\d[^'\":\s]*)", line.rstrip())
            if m:
                name, version = m.group(1), m.group(2)
                if (name, version) not in seen:
                    seen.add((name, version))
                    packages.append({"name": name, "version": version, "ecosystem": "npm"})
    return packages


def _parse_lockfile(path: str) -> list[dict]:
    basename = os.path.basename(path)
    if basename == "package-lock.json":
        return _parse_package_lock(path)
    elif basename in ("requirements.txt", "requirements.in"):
        return _parse_requirements(path)
    elif basename == "go.sum":
        return _parse_go_sum(path)
    elif basename == "go.mod":
        return _parse_go_sum(path)
    elif basename == "yarn.lock":
        return _parse_yarn_lock(path)
    elif basename == "Pipfile.lock":
        return _parse_pipfile_lock(path)
    elif basename == "Cargo.lock":
        return _parse_cargo_lock(path)
    elif basename == "Gemfile.lock":
        return _parse_gemfile_lock(path)
    elif basename == "composer.lock":
        return _parse_composer_lock(path)
    elif basename == "pnpm-lock.yaml":
        return _parse_pnpm_lock(path)
    elif basename.endswith(".json"):
        return _parse_package_lock(path)
    elif basename.endswith(".txt"):
        return _parse_requirements(path)
    return []


def _is_critical(severity) -> bool:
    if not severity:
        return False
    s = str(severity).upper()
    if "CRITICAL" in s:
        return True
    m = _re.search(r"(\d+\.?\d*)", s)
    return m is not None and float(m.group(1)) >= 9.0


def _should_show(vuln: dict, show_all: bool = False) -> bool:
    if show_all:
        return True
    epss = vuln.get("epss", {})
    score = epss.get("score", 1.0) if epss else 1.0
    if score >= 0.1:
        return True
    return _is_critical(vuln.get("severity"))


def _format_results(results: list[dict], pkg_count: int, show_all: bool = False) -> str:
    affected = [r for r in results if r.get("vulnerable")]
    total_vulns = sum(r.get("vuln_count", 0) for r in affected)

    suppressed = 0
    for r in affected:
        for v in r.get("vulns", []):
            if not _should_show(v, show_all):
                suppressed += 1

    lines = []
    lines.append(f"## Scan Results")
    lines.append(f"- **Packages scanned:** {pkg_count}")
    lines.append(f"- **Affected packages:** {len(affected)}")
    lines.append(f"- **Total vulnerabilities:** {total_vulns}")
    if suppressed and not show_all:
        lines.append(f"- **Suppressed (EPSS < 10%, non-critical):** {suppressed}")
    lines.append("")

    if not affected:
        lines.append("No known vulnerabilities found.")
        return "\n".join(lines)

    def max_epss(r):
        scores = [v.get("epss", {}).get("score", 0) if v.get("epss") else 0 for v in r.get("vulns", [])]
        return max(scores) if scores else 0

    affected.sort(key=max_epss, reverse=True)

    for r in affected:
        pkg = r["package"]
        shown_vulns = [v for v in r.get("vulns", []) if _should_show(v, show_all)]
        if not shown_vulns:
            continue

        lines.append(f"### {pkg['name']}@{pkg['version']} — {len(shown_vulns)} vuln{'s' if len(shown_vulns) != 1 else ''}")
        lines.append("")

        for v in shown_vulns:
            cve = v.get("cve") or v.get("id", "unknown")
            parts = [f"**{cve}**"]
            if v.get("severity"):
                parts.append(f"Severity: {v['severity']}")
            if v.get("epss"):
                score = v["epss"]["score"]
                label = "HIGH" if score >= 0.5 else "medium" if score >= 0.1 else "low"
                parts.append(f"EPSS: {score:.1%} ({label})")
            if v.get("fix_version"):
                parts.append(f"Fix: upgrade to {v['fix_version']}")
            lines.append("- " + " | ".join(parts))
            if v.get("summary"):
                summary = v["summary"][:200]
                lines.append(f"  {summary}")
        lines.append("")

    if suppressed and not show_all:
        lines.append(f"*{suppressed} low-priority CVE{'s' if suppressed != 1 else ''} suppressed "
                      f"(EPSS < 10%, CVSS < 9). Use show_all=True to see everything.*")

    return "\n".join(lines)


# --- MCP Tools ---

@mcp.tool()
def scan_lockfile(lockfile_path: str, show_all: bool = False) -> str:
    """Scan a lockfile for known vulnerabilities.

    Reads a package lockfile (package-lock.json, requirements.txt, go.sum),
    queries NVD + GitHub Advisories, enriches with EPSS exploit probability,
    and returns a prioritized vulnerability report with fix recommendations.

    By default, suppresses low-priority CVEs (EPSS < 10% and CVSS < 9).
    Set show_all=True to see every vulnerability.

    Args:
        lockfile_path: Absolute path to the lockfile to scan.
        show_all: Show all vulnerabilities including low-priority ones.
    """
    if not os.path.isfile(lockfile_path):
        return f"Error: file not found: {lockfile_path}"

    packages = _parse_lockfile(lockfile_path)
    if not packages:
        basename = os.path.basename(lockfile_path)
        return f"Error: could not parse packages from {basename}. Supported: package-lock.json, requirements.txt, go.sum"

    data = _query_worker(packages)
    if not data.get("ok"):
        return f"Error: {data.get('error', 'unknown backend error')}"

    return _format_results(data["results"], len(packages), show_all=show_all)


@mcp.tool()
def check_package(name: str, version: str, ecosystem: str = "npm", show_all: bool = False) -> str:
    """Check a single package for known vulnerabilities.

    Args:
        name: Package name (e.g. "express", "django", "golang.org/x/net").
        version: Package version (e.g. "4.18.2", "3.2.0").
        ecosystem: Package ecosystem — "npm", "PyPI", "Go", "crates.io", "RubyGems", or "Packagist". Defaults to "npm".
        show_all: Show all vulnerabilities including low-priority ones.
    """
    valid = ("npm", "PyPI", "Go", "crates.io", "RubyGems", "Packagist")
    if ecosystem not in valid:
        return f"Error: unsupported ecosystem '{ecosystem}'. Use one of: {', '.join(valid)}."

    data = _query_worker([{"name": name, "version": version, "ecosystem": ecosystem}])
    if not data.get("ok"):
        return f"Error: {data.get('error', 'unknown backend error')}"

    results = data.get("results", [])
    if not results or not results[0].get("vulnerable"):
        return f"No known vulnerabilities for {name}@{version} ({ecosystem})."

    return _format_results(results, 1, show_all=show_all)


def _format_paywall(cve_id: str, body: str) -> str:
    """Render an HTTP 402 from the paid CVE endpoint as a legible paywall.

    lookup_cve maps to a pay-per-call x402 endpoint, so free/keyless clients get a
    402. Surface that as a clear paywall — with the free alternatives and the x402
    challenge preserved for machine clients — instead of a raw "Backend HTTP 402"
    error dump that reads like the tool is broken.
    """
    lines = [
        f"🔒 lookup_cve for {cve_id} requires payment — it is a pay-per-call "
        "endpoint ($0.002 per lookup, settled over x402 on Base).",
        "",
        "Free & keyless (no payment needed) — use these instead:",
        "  • check_package — check a specific package@version for known CVEs (EPSS-ranked)",
        "  • scan_lockfile / scan_project — scan your dependencies, prioritized by exploit probability",
        "",
        "To use lookup_cve: set VULNFEED_API_KEY, or pay per call with an x402-capable client.",
    ]
    try:
        challenge = json.loads(body)
        res = challenge.get("resource") or {}
        if isinstance(res, dict):
            url = res.get("url") or res.get("resource")
            if url:
                lines.append(f"  x402 resource: {url}")
    except Exception:
        pass
    return "\n".join(lines)


@mcp.tool()
def lookup_cve(cve_id: str) -> str:
    """Look up detailed information about a specific vulnerability.

    Returns full details including severity, EPSS exploit probability,
    affected packages, fix versions, and references.

    Args:
        cve_id: Vulnerability ID (e.g. "CVE-2024-29041", "GHSA-rv95-896h-c2vc").
    """
    req = urllib.request.Request(
        f"{WORKER_URL}/vulnscan/cve/{urllib.request.quote(cve_id, safe='')}",
        headers=_auth_headers(),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"Vulnerability {cve_id} not found in NVD/GHSA databases."
        body = e.read().decode() if e.fp else ""
        if e.code == 402:
            return _format_paywall(cve_id, body)
        return f"Error: Backend HTTP {e.code}: {body}"
    except Exception as e:
        return f"Error: Backend unreachable: {e}"

    if not data.get("ok"):
        return f"Error: {data.get('error', 'unknown')}"

    lines = []
    lines.append(f"## {data['id']}")
    if data.get("cve") and data["cve"] != data["id"]:
        lines.append(f"**CVE:** {data['cve']}")
    if data.get("summary"):
        lines.append(f"\n{data['summary']}")
    if data.get("details"):
        details = data["details"][:500]
        lines.append(f"\n{details}")

    if data.get("severity"):
        for s in data["severity"]:
            lines.append(f"\n**Severity:** {s.get('score', s.get('type', 'unknown'))}")

    if data.get("epss"):
        score = data["epss"]["score"]
        pct = data["epss"]["percentile"]
        label = "HIGH" if score >= 0.5 else "medium" if score >= 0.1 else "low"
        lines.append(f"**EPSS:** {score:.1%} ({label}) — more exploitable than {pct:.0%} of all CVEs")

    if data.get("affected_packages"):
        lines.append("\n### Affected packages")
        for pkg in data["affected_packages"]:
            fix = ", ".join(pkg["fix_versions"]) if pkg.get("fix_versions") else "no fix available"
            lines.append(f"- **{pkg['name']}** ({pkg['ecosystem']}) — fix: {fix}")

    if data.get("aliases"):
        lines.append(f"\n**Aliases:** {', '.join(data['aliases'])}")

    if data.get("references"):
        lines.append("\n### References")
        for ref in data["references"][:5]:
            lines.append(f"- [{ref.get('type', 'link')}]({ref['url']})")

    lines.append(f"\n**Published:** {data.get('published', 'unknown')}")
    return "\n".join(lines)


@mcp.tool()
def scan_project(project_path: str = ".", show_all: bool = False) -> str:
    """Auto-detect and scan all lockfiles in a project directory.

    Walks the project directory looking for lockfiles (package-lock.json,
    requirements.txt, go.sum, etc.) and scans each one. Skips node_modules,
    .git, and vendor directories.

    By default, suppresses low-priority CVEs (EPSS < 10% and CVSS < 9).

    Args:
        project_path: Path to the project root. Defaults to current directory.
        show_all: Show all vulnerabilities including low-priority ones.
    """
    project = Path(project_path).resolve()
    if not project.is_dir():
        return f"Error: not a directory: {project_path}"

    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", ".venv", "venv", ".tox"}
    found = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f in LOCKFILE_NAMES:
                found.append(os.path.join(root, f))

    if not found:
        return f"No lockfiles found in {project_path}. Supported: {', '.join(sorted(LOCKFILE_NAMES))}"

    all_output = []
    total_packages = 0
    total_vulns = 0

    for lockfile in found:
        packages = _parse_lockfile(lockfile)
        if not packages:
            all_output.append(f"### {os.path.relpath(lockfile, project)}\nSkipped — unsupported or empty.\n")
            continue

        data = _query_worker(packages)
        if not data.get("ok"):
            all_output.append(f"### {os.path.relpath(lockfile, project)}\nError: {data.get('error')}\n")
            continue

        results = data.get("results", [])
        total_packages += len(packages)
        total_vulns += sum(r.get("vuln_count", 0) for r in results if r.get("vulnerable"))

        rel = os.path.relpath(lockfile, project)
        all_output.append(f"# {rel}\n")
        all_output.append(_format_results(results, len(packages), show_all=show_all))
        all_output.append("")

    header = f"**Project scan:** {len(found)} lockfile{'s' if len(found) != 1 else ''} found, {total_packages} packages, {total_vulns} vulnerabilities\n"
    return header + "\n".join(all_output)


def _auth_headers(content_type=None):
    h = {"User-Agent": "vulnfeed-mcp/0.3"}
    if WORKER_KEY:
        h["Authorization"] = f"Bearer {WORKER_KEY}"
    if content_type:
        h["Content-Type"] = content_type
    return h


def _post_worker(path: str, body: dict) -> dict:
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{WORKER_URL}{path}",
        data=payload,
        headers=_auth_headers("application/json"),
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        return {"ok": False, "error": f"Backend HTTP {e.code}: {body_text}"}
    except Exception as e:
        return {"ok": False, "error": f"Backend unreachable: {e}"}


def _get_worker(path: str) -> dict:
    req = urllib.request.Request(
        f"{WORKER_URL}{path}",
        headers=_auth_headers(),
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        return {"ok": False, "error": f"Backend HTTP {e.code}: {body_text}"}
    except Exception as e:
        return {"ok": False, "error": f"Backend unreachable: {e}"}


def _put_worker(path: str, body: dict) -> dict:
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{WORKER_URL}{path}",
        data=payload,
        method="PUT",
        headers=_auth_headers("application/json"),
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        return {"ok": False, "error": f"Backend HTTP {e.code}: {body_text}"}
    except Exception as e:
        return {"ok": False, "error": f"Backend unreachable: {e}"}


def _delete_worker(path: str) -> dict:
    req = urllib.request.Request(
        f"{WORKER_URL}{path}",
        method="DELETE",
        headers=_auth_headers(),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        return {"ok": False, "error": f"Backend HTTP {e.code}: {body_text}"}
    except Exception as e:
        return {"ok": False, "error": f"Backend unreachable: {e}"}


@mcp.tool()
def monitor_project(project_path: str = ".", project_name: str = "", webhook_url: str = "") -> str:
    """Register a project for continuous vulnerability monitoring.

    Scans the project's lockfiles, records the current vulnerability baseline,
    and stores a snapshot. Use check_alerts later to see new vulnerabilities
    that appeared since registration.

    With webhook_url set, VulnFeed re-scans the project on a schedule (hourly on
    the paid tier, daily on the free tier) and POSTs any NEW findings to that URL
    as JSON, signed with HMAC-SHA256 in the X-VulnFeed-Signature header using the
    webhook_secret returned here — once. Without it, monitoring is pull-only:
    nothing happens until check_alerts is called.

    Args:
        project_path: Path to the project root. Defaults to current directory.
        project_name: Human-readable name for the project. Defaults to directory name.
        webhook_url: Optional https URL to receive new findings (CI hook, Slack/Discord
            relay, your own endpoint). Must be a public https hostname. Requires
            VULNFEED_API_KEY (webhooks are a paid feature).
    """
    project = Path(project_path).resolve()
    if not project.is_dir():
        return f"Error: not a directory: {project_path}"

    if webhook_url and not WORKER_KEY:
        return (
            "Webhook (push) monitoring is a paid feature. Set VULNFEED_API_KEY to a license key "
            "(https://vulnfeed.novadyne.ai, $14/mo, unlimited projects, no expiry), or — for agents "
            "paying per use — POST /vulnscan/monitor over x402 ($0.50 per project per 30 days of "
            "hourly monitoring). Re-run without webhook_url to register on the free tier (pull-only "
            "via check_alerts)."
        )

    if not project_name:
        project_name = project.name

    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", ".venv", "venv", ".tox"}
    found = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f in LOCKFILE_NAMES:
                found.append(os.path.join(root, f))

    if not found:
        return f"No lockfiles found in {project_path}. Cannot register for monitoring."

    all_packages = []
    for lockfile in found:
        packages = _parse_lockfile(lockfile)
        all_packages.extend(packages)

    if not all_packages:
        return "Error: lockfiles found but could not parse any packages."

    seen = set()
    deduped = []
    for p in all_packages:
        key = (p["name"], p["version"], p.get("ecosystem", "npm"))
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    body = {"project_name": project_name, "packages": deduped}
    if webhook_url:
        body["notify"] = {"webhook": webhook_url}
    data = _post_worker("/vulnscan/monitor", body)

    if not data.get("ok"):
        detail = data.get("detail")
        return f"Error: {data.get('error', 'unknown')}" + (f" — {detail}" if detail else "")

    lines = [
        f"## Project Registered for Monitoring",
        f"- **Name:** {data.get('name', project_name)}",
        f"- **Project ID:** `{data['project_id']}`",
        f"- **Packages:** {data.get('packages_count', len(deduped))}",
        f"- **Known vulnerabilities baselined:** {data.get('initial_vulns', 0)}",
        "",
        "Use `check_alerts` with this project ID to check for new vulnerabilities.",
        f"Use `list_monitored` to see all monitored projects.",
    ]

    if data.get("webhook"):
        lines += [
            "",
            "### Webhook",
            f"- **URL:** {data['webhook']}",
            f"- **Secret (shown once — store it now):** `{data.get('webhook_secret', '')}`",
            "- New findings are POSTed as JSON with header `X-VulnFeed-Signature: sha256=<hex>`,",
            "  the HMAC-SHA256 of the raw request body under this secret. Verify it before trusting a delivery.",
            "- Change or remove the webhook later with `set_webhook`.",
        ]

    if data.get("initial_vulns", 0) > 0:
        lines.append("")
        lines.append(f"*{data['initial_vulns']} existing vulnerabilities recorded as baseline — "
                      f"they won't appear as new alerts. Run `scan_project` for full details.*")

    return "\n".join(lines)


@mcp.tool()
def set_webhook(project_id: str, webhook_url: str = "") -> str:
    """Set, rotate or remove the webhook for a monitored project.

    Setting a URL (even the same one) mints a NEW signing secret and returns it
    once. Passing an empty webhook_url removes the webhook; monitoring continues
    pull-only via check_alerts.

    Args:
        project_id: Project ID from monitor_project / list_monitored.
        webhook_url: https URL to receive new findings, or "" to remove.
    """
    data = _put_worker(f"/vulnscan/monitor/{project_id}/notify", {"webhook": webhook_url or None})
    if not data.get("ok"):
        detail = data.get("detail")
        return f"Error: {data.get('error', 'unknown')}" + (f" — {detail}" if detail else "")
    if not data.get("webhook"):
        return f"Webhook removed for `{project_id}`. {data.get('message', '')}".strip()
    return "\n".join([
        f"## Webhook set for `{project_id}`",
        f"- **URL:** {data['webhook']}",
        f"- **Secret (shown once — store it now):** `{data.get('webhook_secret', '')}`",
        "- Deliveries carry `X-VulnFeed-Signature: sha256=<hex>` = HMAC-SHA256(secret, raw body).",
    ])


@mcp.tool()
def check_alerts(project_id: str) -> str:
    """Check for new vulnerabilities since the last scan of a monitored project.

    Compares current vulnerability data against the stored baseline.
    Returns new vulnerabilities (not seen before) and resolved ones
    (previously known, no longer present).

    Args:
        project_id: The project ID returned by monitor_project.
    """
    data = _get_worker(f"/vulnscan/alerts?project={urllib.request.quote(project_id, safe='')}")

    if not data.get("ok"):
        error = data.get("error", "unknown")
        if "not_found" in str(error):
            return f"Project `{project_id}` not found. Use `monitor_project` to register first, or `list_monitored` to see registered projects."
        return f"Error: {error}"

    lines = []
    lines.append(f"## Vulnerability Alerts — {data.get('project_name', project_id)}")
    lines.append(f"- **Last scanned:** {data.get('last_scanned_at', 'unknown')[:19]}Z")
    lines.append(f"- **Total known vulnerabilities:** {data.get('total_known_vulns', 0)}")
    lines.append(f"- **Scan count:** {data.get('scan_count', 0)}")
    lines.append("")

    new_vulns = data.get("new_vulns", [])
    resolved = data.get("resolved_vulns", [])

    if new_vulns:
        lines.append(f"### ⚠️ {len(new_vulns)} New Vulnerabilit{'y' if len(new_vulns) == 1 else 'ies'}")
        lines.append("")
        for v in new_vulns:
            parts = [f"**{v.get('id', 'unknown')}**"]
            if v.get("package"):
                ver = f"@{v['version']}" if v.get("version") else ""
                parts.append(f"in {v['package']}{ver}")
            if v.get("severity"):
                parts.append(f"Severity: {v['severity']}")
            if v.get("epss"):
                score = v["epss"]["score"]
                label = "HIGH" if score >= 0.5 else "medium" if score >= 0.1 else "low"
                parts.append(f"EPSS: {score:.1%} ({label})")
            if v.get("fix_version"):
                parts.append(f"Fix: upgrade to {v['fix_version']}")
            lines.append("- " + " | ".join(parts))
            if v.get("summary"):
                lines.append(f"  {v['summary'][:200]}")
        lines.append("")

    if resolved:
        lines.append(f"### ✅ {len(resolved)} Resolved")
        lines.append("")
        for v in resolved:
            pkg = f" (in {v['package']})" if v.get("package") else ""
            lines.append(f"- {v.get('id', 'unknown')}{pkg} — first seen {v.get('first_seen', 'unknown')[:10]}")
        lines.append("")

    if not new_vulns and not resolved:
        lines.append("No changes since last scan. Your dependencies are stable.")

    return "\n".join(lines)


@mcp.tool()
def list_monitored() -> str:
    """List all projects registered for vulnerability monitoring.

    Shows project names, IDs, package counts, and registration dates.
    """
    data = _get_worker("/vulnscan/projects")

    if not data.get("ok"):
        return f"Error: {data.get('error', 'unknown')}"

    projects = data.get("projects", [])
    if not projects:
        return "No projects registered for monitoring. Use `monitor_project` to register one."

    lines = [f"## Monitored Projects ({len(projects)})"]
    lines.append("")
    for p in projects:
        lines.append(f"- **{p.get('name', 'unnamed')}** — ID: `{p['id']}`, "
                      f"{p.get('packages_count', '?')} packages, "
                      f"registered {p.get('created_at', 'unknown')[:10]}")
    lines.append("")
    lines.append("Use `check_alerts` with a project ID to check for new vulnerabilities.")

    return "\n".join(lines)


@mcp.tool()
def update_deps(project_id: str, project_path: str = ".") -> str:
    """Update a monitored project's dependency snapshot after upgrading packages.

    Re-reads lockfiles from the project directory and updates the stored
    dependency list. Preserves vulnerability history: existing known vulns
    that still apply are kept; new vulns from upgraded deps are flagged;
    vulns from removed deps are marked resolved.

    Args:
        project_id: The project ID to update.
        project_path: Path to the project root. Defaults to current directory.
    """
    project = Path(project_path).resolve()
    if not project.is_dir():
        return f"Error: not a directory: {project_path}"

    skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", ".venv", "venv", ".tox"}
    found = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f in LOCKFILE_NAMES:
                found.append(os.path.join(root, f))

    if not found:
        return f"No lockfiles found in {project_path}."

    all_packages = []
    for lockfile in found:
        packages = _parse_lockfile(lockfile)
        all_packages.extend(packages)

    if not all_packages:
        return "Error: lockfiles found but could not parse any packages."

    seen = set()
    deduped = []
    for p in all_packages:
        key = (p["name"], p["version"], p.get("ecosystem", "npm"))
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    data = _put_worker(
        f"/vulnscan/monitor/{urllib.request.quote(project_id, safe='')}",
        {"packages": deduped},
    )

    if not data.get("ok"):
        error = data.get("error", "unknown")
        if "not_found" in str(error):
            return f"Project `{project_id}` not found. Use `monitor_project` to register first."
        return f"Error: {error}"

    lines = [
        f"## Dependencies Updated",
        f"- **Project ID:** `{data.get('project_id', project_id)}`",
        f"- **Packages:** {data.get('packages_count', len(deduped))}",
        f"- **Known vulnerabilities:** {data.get('total_known_vulns', '?')}",
    ]

    new_count = data.get("new_vulns", 0)
    resolved_count = data.get("resolved_vulns", 0)

    if new_count > 0:
        lines.append(f"- **New vulnerabilities:** {new_count}")
    if resolved_count > 0:
        lines.append(f"- **Resolved by upgrade:** {resolved_count}")

    if new_count == 0 and resolved_count > 0:
        lines.append("")
        lines.append(f"Upgrade resolved {resolved_count} vulnerabilit{'y' if resolved_count == 1 else 'ies'}.")
    elif new_count > 0:
        lines.append("")
        lines.append("Run `check_alerts` for details on the new vulnerabilities.")

    return "\n".join(lines)


@mcp.tool()
def unmonitor_project(project_id: str) -> str:
    """Remove a project from vulnerability monitoring.

    Deletes the stored dependency snapshot and vulnerability baseline.

    Args:
        project_id: The project ID to remove.
    """
    data = _delete_worker(f"/vulnscan/monitor/{urllib.request.quote(project_id, safe='')}")

    if not data.get("ok"):
        error = data.get("error", "unknown")
        if "not_found" in str(error):
            return f"Project `{project_id}` not found."
        return f"Error: {error}"

    return f"Project `{project_id}` removed from monitoring."


def main():
    import argparse
    parser = argparse.ArgumentParser(description="VulnFeed MCP Server")
    parser.add_argument(
        "--transport", choices=["stdio", "sse"],
        default=os.environ.get("VULNFEED_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8383)
    args = parser.parse_args()

    if args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
