<!-- mcp-name: io.github.novadyne-hq/vulnfeed -->
# VulnFeed — Dependency Vulnerability Monitoring for Claude Code

[![CI](https://github.com/novadyne-hq/vulnfeed-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/novadyne-hq/vulnfeed-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vulnfeed-mcp)](https://pypi.org/project/vulnfeed-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![vulnfeed-mcp MCP server](https://glama.ai/mcp/servers/novadyne-hq/vulnfeed-mcp/badges/score.svg)](https://glama.ai/mcp/servers/novadyne-hq/vulnfeed-mcp)

An MCP server that scans your project dependencies for known vulnerabilities, enriches with EPSS exploit probability scores, and recommends fix versions.

**Free tier** — 10 scans/day, 1 monitored project, no signup required.

**Homepage:** [vulnfeed.novadyne.ai](https://vulnfeed.novadyne.ai)

## Install

```bash
uvx vulnfeed-mcp
```

### MCP client config

Add to your MCP client config (`~/.claude/settings.json` for Claude Code, `claude_desktop_config.json` for Claude Desktop):

**Free tier** (no signup, no API key):
```json
{
  "mcpServers": {
    "vulnfeed": {
      "command": "uvx",
      "args": ["vulnfeed-mcp"]
    }
  }
}
```

**Paid** ($14/mo, unlimited scans + projects):
```json
{
  "mcpServers": {
    "vulnfeed": {
      "command": "uvx",
      "args": ["vulnfeed-mcp"],
      "env": {
        "VULNFEED_API_KEY": "YOUR_LICENSE_KEY_HERE"
      }
    }
  }
}
```

Get a license key at [vulnfeed.novadyne.ai](https://vulnfeed.novadyne.ai).

### x402 micropayments

VulnFeed also accepts [x402](https://x402.org) micropayments — AI agents can pay per scan with USDC on Base, no API key or signup needed. When the free tier limit is reached, the API returns HTTP 402 with payment requirements that x402-compatible clients handle automatically.

- $0.01 per scan
- $0.002 per CVE lookup
- $0.05 per project monitor setup

## Tools

### Scanning

| Tool | Description |
|------|-------------|
| `scan_project` | Auto-detect and scan all lockfiles in a directory |
| `scan_lockfile` | Scan a specific lockfile |
| `check_package` | Check a single package for vulnerabilities |
| `lookup_cve` | Detailed CVE info with EPSS + fix versions |

### Monitoring

| Tool | Description |
|------|-------------|
| `monitor_project` | Register for continuous monitoring |
| `check_alerts` | New vulns since last scan |
| `update_deps` | Update snapshot after upgrading packages |
| `list_monitored` | See all monitored projects |
| `unmonitor_project` | Remove from monitoring |

## Supported lockfiles

- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `pnpm-lock.yaml` (pnpm)
- `requirements.txt` (pip)
- `Pipfile.lock` (Pipenv)
- `go.sum` / `go.mod` (Go)
- `Cargo.lock` (Rust)
- `Gemfile.lock` (Ruby)
- `composer.lock` (PHP)

## How it works

1. Parses your lockfile to extract dependency names + versions
2. Queries OSV.dev (NVD + GitHub Advisories) for known CVEs
3. Enriches with EPSS exploit probability scores
4. Filters noise — suppresses low-EPSS, non-critical CVEs by default
5. Sorts by exploitability — most likely to be exploited first
6. Returns fix version recommendations from package registries

### Smart filtering

By default, VulnFeed suppresses low-priority CVEs (EPSS < 10% AND CVSS < 9.0). This cuts noise by ~80%.

Pass `show_all=True` to any scan tool to see everything.

### Continuous monitoring

1. `monitor_project` — takes a baseline snapshot of current deps + known vulns
2. `check_alerts` — diffs against baseline, surfaces only new vulns
3. Run `check_alerts` periodically to catch newly published CVEs

## License

MIT
