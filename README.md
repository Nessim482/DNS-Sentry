# DNS-Sentry

[Version française](README.fr.md)

DNS-Sentry is a defensive cybersecurity tool that detects possible DNS tunneling attempts by analyzing the Shannon entropy of DNS query subdomains.

It detects and alerts only. It does not block traffic.

## Features

- Shannon entropy calculation for DNS subdomains.
- Domain analyzer with configurable entropy threshold.
- Simple DNS log/query parser.
- Real-time DNS monitoring with Scapy.
- Discord webhook alerts with structured embeds.
- Configuration through `.env` using `python-dotenv`.
- Command-line interface with `argparse`.
- Tkinter GUI with the DNS-Sentry icon when available.
- Demo mode that runs without live packet capture.
- Secure logging that avoids exposing sensitive webhook values.
- Pytest test suite.
- GitHub Actions workflow for automated checks.
- Dependencies declared in `pyproject.toml`.

## How It Works

DNS-Sentry watches DNS queries and extracts the queried domain name. The analyzer focuses on the subdomain portion, computes its Shannon entropy, and compares the result with a configured threshold.

High-entropy subdomains may indicate encoded or random-looking payloads often seen in DNS tunneling. This is a heuristic signal, not proof of malicious activity.

When a query is considered suspicious, DNS-Sentry logs the event and can send a Discord alert if a webhook is configured.

## Installation

Install the project in editable mode with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

After installation, the package can be run with either:

```bash
python -m dns_sentry
```

or the console command:

```bash
dns-sentry
```

## System Requirements

- Python 3.10 or newer.
- `pip` for installation.
- Scapy for live DNS monitoring.
- Network capture permissions for real monitoring.
- Tkinter for the GUI. It is included with many Python installations, but some systems package it separately.

Tests and demo mode do not require Npcap or real packet capture.

## Windows Npcap Requirement

On Windows, live DNS monitoring requires Npcap.

Npcap is not installed by `pip` and must be installed separately from the official Npcap installer. Real monitoring may also require running the terminal as Administrator.

The following commands do not require Npcap:

```bash
python -m pytest
python -m dns_sentry --demo
python -m dns_sentry --check-env
```

## Linux/macOS Permission Note

Live DNS monitoring requires Scapy and permission to capture network traffic. On Linux or macOS, you may need to run the command with elevated privileges or configure packet capture permissions for your environment.

Demo mode and tests do not require network capture permissions.

## Configuration With `.env`

Create a local `.env` file from `.env.example` when needed:

```env
DISCORD_WEBHOOK_URL=
DNS_ENTROPY_THRESHOLD=4.0
DNS_INTERFACE=Wi-Fi
DNS_DEBUG=false
```

Configuration values:

- `DISCORD_WEBHOOK_URL`: optional Discord webhook URL for alerts.
- `DNS_ENTROPY_THRESHOLD`: entropy threshold used to flag suspicious domains.
- `DNS_INTERFACE`: optional network interface name for live monitoring.
- `DNS_DEBUG`: set to `true` to enable debug logging.

Security rules:

- `.env` must never be committed.
- `.env.example` is safe to commit because it contains no real secret.
- A Discord webhook URL is a secret and must stay private.
- Do not commit tokens, webhooks, real `.env` files, packet captures, or logs containing private data.

## CLI Usage

Check dependencies and configuration loading without sniffing traffic:

```bash
python -m dns_sentry --check-env
```

Run demo mode without live packet capture:

```bash
python -m dns_sentry --demo
dns-sentry --demo
```

Run live DNS monitoring with an explicit interface and threshold:

```bash
python -m dns_sentry --interface Wi-Fi --threshold 4.0
```

Live monitoring requires Scapy and network capture permissions.

## GUI Usage

Start the Tkinter GUI:

```bash
python -m dns_sentry --gui
dns-sentry --gui
```

The GUI allows you to set the network interface, entropy threshold, optional Discord webhook, and debug logging. It can start live monitoring, stop monitoring, and run demo mode.

Real monitoring from the GUI has the same Scapy, Npcap, and permission requirements as the CLI.

## Demo Mode

Demo mode analyzes built-in sample domains and does not capture real network traffic.

```bash
python -m dns_sentry --demo
dns-sentry --demo
```

Demo mode is useful for checking the analyzer, logging, and optional Discord alert path without requiring Npcap or packet capture permissions.

## Discord Alerts

If `DISCORD_WEBHOOK_URL` is configured, DNS-Sentry can send a Discord webhook alert when a suspicious DNS query is detected.

Alerts include the domain, subdomain, entropy score, threshold, severity label, and UTC timestamp.

Keep the webhook secret. Do not paste a real webhook into documentation, tickets, logs, commits, or screenshots.

## Running Tests

Install development dependencies and run the test suite:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Tests do not require Npcap or real network capture.

## GitHub Actions

The repository includes a GitHub Actions workflow that runs on pushes and pull requests. It installs the project, runs pytest, checks environment loading, and runs demo mode on Python 3.11 and 3.12.

No real Discord webhook is required for CI.

## Security Notes

- DNS-Sentry is a detection and alerting tool only.
- It does not block DNS traffic or stop attacks.
- Keep `.env` files, Discord webhooks, captures, and private logs out of commits.
- The repository ignores `.env`, `.env.*` except `.env.example`, packet captures, logs, Python cache files, and build metadata.
- Use the tool only on systems and networks where you have authorization.

## Known Limitations

- Detection is based on Shannon entropy and can produce false positives.
- Low-entropy tunneling or other evasion techniques may not be detected.
- The live sniffer focuses on DNS queries visible to Scapy, not encrypted DNS such as DoH or DoT.
- Interface names vary by operating system and network configuration.
- DNS-Sentry is not a replacement for a professional IDS, SIEM, EDR, or full network monitoring stack.

## Defensive and Legal Disclaimer

DNS-Sentry is intended for defensive monitoring, education, and authorized security testing. Use it only on networks and systems you own or are explicitly allowed to monitor.

You are responsible for complying with applicable laws, policies, and privacy requirements.
