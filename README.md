<!-- mcp-name: io.github.novadyne-hq/vulnfeed -->
# VulnFeed — Dependency Vulnerability Monitoring for Claude Code

[![CI](https://github.com/novadyne-hq/vulnfeed-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/novadyne-hq/vulnfeed-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vulnfeed-mcp)](https://pypi.org/project/vulnfeed-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![vulnfeed-mcp MCP server](https://glama.ai/mcp/servers/novadyne-hq/vulnfeed-mcp/badges/score.svg)](https://glama.ai/mcp/servers/novadyne-hq/vulnfeed-mcp)

An MCP server that scans your project dependencies for known vulnerabilities, enriches with EPSS exploit probability scores, and recommends fix versions.

**Free tier** — 10 scans/day, 1 monitored project, no signup required. Single-CVE lookup and webhooks need a license key or x402.

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
- $0.50 per project per 30 days of hourly webhook monitoring (renewable; the webhook receives an `expiring` event with the renew URL a day before)

## Tools

### Scanning

| Tool | Description |
|------|-------------|
| `scan_project` | Auto-detect and scan all lockfiles in a directory |
| `scan_lockfile` | Scan a specific lockfile |
| `check_package` | Check a single package for vulnerabilities |
| `lookup_cve` | Detailed CVE info with EPSS + fix versions (license key or x402) |

### Monitoring

| Tool | Description |
|------|-------------|
| `monitor_project` | Register for continuous monitoring (optional `webhook_url` for push alerts) |
| `check_alerts` | New vulns since last scan |
| `set_webhook` | Set, rotate or remove a project's webhook |
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
2. Queries OSV.dev (GitHub Advisories plus each ecosystem's security database) for known CVEs
3. Enriches with EPSS exploit probability scores
4. Filters noise — suppresses low-EPSS, non-critical CVEs by default
5. Sorts by exploitability — most likely to be exploited first
6. Returns fix versions from each advisory's affected-version ranges

### Smart filtering

By default, VulnFeed suppresses low-priority CVEs (EPSS < 10% AND CVSS < 9.0). This cuts noise by ~80%.

Pass `show_all=True` to any scan tool to see everything.

### Continuous monitoring

1. `monitor_project` — takes a baseline snapshot of current deps + known vulns
2. `check_alerts` — diffs against baseline, surfaces only new vulns
3. Either run `check_alerts` periodically, **or pass `webhook_url`** and let VulnFeed do it

With a webhook (a paid feature: a license key, or for agents x402 at $0.50 per project per 30-day
term), VulnFeed re-scans the project every hour and POSTs new findings to your URL:

```json
{
  "event": "vulnfeed.new_vulns",
  "delivery_id": "…", "project_id": "…", "project_name": "…", "sent_at": "…",
  "count": 1,
  "new_vulns": [{ "id": "GHSA-…", "package": "express", "version": "4.18.2", "severity": "HIGH",
                  "epss": { "score": 0.42 }, "fix_version": "4.19.2", "summary": "…" }],
  "alerts_url": "https://vulnfeed-api.novadyne.ai/vulnscan/alerts?project=…"
}
```

Every delivery carries `X-VulnFeed-Signature: sha256=<hex>`, the HMAC-SHA256 of the raw body under
the `webhook_secret` returned once when the webhook was set. Verify it. Failed deliveries are retried
on later sweeps for about a day, then dropped and counted. Rotate or remove the webhook with
`set_webhook`.

## License

MIT
