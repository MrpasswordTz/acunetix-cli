# AcuScan CLI v3.0

> **FREE, professional command-line vulnerability scanner powered by Acunetix.**  
> No setup needed — install and start scanning immediately.  
> A public Acunetix server is built right into the tool, provided free by MrpasswordTz.

### Author

**MrpasswordTz** — [GitHub](https://github.com/MrpasswordTz)  
**Powered by:** MrpasswordTz

---

## Why AcuScan CLI?

**Most vulnerability scanners require you to buy a license and set up a server.**  
AcuScan CLI is different — it ships with a **free public Acunetix instance** built in.

```
Install → Scan → Done.  No API keys, no accounts, no cost.
```

> Want to use your own Acunetix server? Just run `acuscanner --setup` to override.

---

## Highlights

| Feature | Description |
|---------|-------------|
| **FREE Public Server** | Built-in Acunetix instance — no setup, no API key needed |
| **Zero Configuration** | Install and scan immediately out of the box |
| **Multi-User Profiles** | Named configs per user — switch identities/servers |
| **Scan Ownership** | Track who started which scan with `--my-scans` |
| **Live Monitoring** | `--watch-scan` with real-time vulnerability alerts |
| **Batch Operations** | Bulk scan URLs, batch-generate reports |
| **Rich Reports** | Auto-download PDF/HTML, batch across scans |
| **Beautiful CLI** | Categorised `--help`, color-coded severity, rich dashboard |
| **Resilient API** | Automatic retry with exponential backoff, rate-limit handling |
| **Flexible Output** | Table, JSON, CSV for every list command |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Acunetix Server                         │
│  (All scans, targets, reports are instance-level data)   │
│                                                          │
│   Users:  alice@co.com (admin)  ·  bob@co.com (user)     │
└─────────────────────┬────────────────────────────────────┘
                      │  REST API (HTTPS)
          ┌───────────┴──────────┐
          │                      │
   ┌──────┴──────┐        ┌──────┴──────┐
   │  Alice's PC │        │  Bob's PC   │
   │  acuscanner │        │  acuscanner │
   │  profile:   │        │  profile:   │
   │   default   │        │   default   │
   │   (her key) │        │   (his key) │
   └─────────────┘        └─────────────┘
```

**Key concept:** Acunetix is _instance-level_. All authenticated users on the same server
see the same targets, scans, and reports. This is by design — it's a shared security tool.

AcuScan CLI adds a **local profile layer** so each person stores their own API key
and can filter to scans they started.

---

## Installation

### Quick Install (Linux)

```bash
git clone https://github.com/MrpasswordTz/acunetix-cli.git
cd acunetix-cli
chmod +x install.sh
sudo ./install.sh
```

Supports **Debian/Ubuntu**, **RHEL/CentOS/Fedora**, and **macOS** (via brew).

### Manual / Development Setup

```bash
git clone https://github.com/MrpasswordTz/acunetix-cli.git
cd acunetix-cli
pip3 install -r requirements.txt
python3 scanner.py --help
```

---

## Quick Start

After installing, **no configuration is needed**. The tool uses the free public server automatically:

```bash
# Start scanning immediately — no setup required!
acuscanner --scan -u https://example.com

# List your scans
acuscanner --list-scans

# Check who you're connected as
acuscanner --whoami
```

---

## Configuration (Optional)

If you want to use **your own Acunetix server** instead of the public one:

### Connect Your Own Server

```bash
acuscanner --setup
```

This creates a profile at `cli/were/.env`:

```env
ACUNETIX_URL=https://YOUR_SERVER:3443/api/v1
ACUNETIX_API_KEY=YOUR_API_KEY
ACUNETIX_VERIFY_SSL=false
ACUNETIX_TIMEOUT=30
```

### Test Your Connection

```bash
acuscanner --test-connection
```

### See Who You're Authenticated As

```bash
acuscanner --whoami
```

---

## Multi-User / Team Setup

This is how you handle **multiple people using the same Acunetix instance** from different locations.

### Step 1 — Each User Gets an Acunetix Account

In the Acunetix web UI, an admin creates user accounts. Each user gets their own **API Key**
from `Profile → API Key` in the Acunetix dashboard.

### Step 2 — Each User Configures Their CLI

**On Alice's machine:**
```bash
acuscanner --setup
# Enter Alice's URL and API key
```

**On Bob's machine:**
```bash
acuscanner --setup
# Enter Bob's URL and API key
```

### Step 3 — Both Users Work Independently

```bash
# Alice starts a scan
alice$ acuscanner --scan -u https://target.com

# Bob lists ALL scans (including Alice's) — this is normal!
bob$ acuscanner --list-scans

# Bob sees only HIS scans
bob$ acuscanner --my-scans
```

### Named Profiles (Advanced)

If one person manages **multiple Acunetix instances** or needs to switch between API keys:

```bash
# Create profiles
acuscanner --add-profile production
acuscanner --add-profile staging

# Use a specific profile for any command
acuscanner --use-profile production --list-scans
acuscanner --use-profile staging --scan -u https://staging.app.com

# List all saved profiles
acuscanner --list-profiles-config

# Delete a profile
acuscanner --del-profile-config staging
```

### How Scan Sharing Works

| Scenario | What Happens |
|----------|-------------|
| Alice starts a scan | Both Alice and Bob see it in `--list-scans` |
| Bob runs `--my-scans` | Only shows scans Bob started from his CLI |
| Alice runs `--my-scans` | Only shows scans Alice started from her CLI |
| Bob generates a report on Alice's scan | Works perfectly — scans are shared |
| Alice aborts Bob's scan | Works if Alice has the right permissions |
| Two users `--list-scans` at the same time | No conflict — the API handles concurrent reads |

---

## Usage

### Starting Scans

```bash
# Basic scan
acuscanner --scan -u https://example.com

# Scan with a specific profile
acuscanner --scan -u https://example.com --profile-id PROFILE_UUID

# Scheduled scan
acuscanner --scan -u https://example.com --schedule "2026-06-01T09:00:00"

# Bulk scan from file
acuscanner --bulk-scan urls.txt --delay 10
```

### Managing Scans

```bash
# List recent scans
acuscanner --list-scans --limit 30

# List only YOUR scans
acuscanner --my-scans

# Filter by status
acuscanner --list-scans --filter-status completed
acuscanner --list-scans --filter-status processing

# Filter by target URL
acuscanner --list-scans --filter-target example.com

# Combine filters
acuscanner --list-scans --filter-status completed --filter-target prod --limit 50

# Watch scan live
acuscanner --watch-scan SCAN_ID --interval 10

# Get detailed status
acuscanner --scan-status SCAN_ID

# Abort a running scan
acuscanner --abort-scan SCAN_ID

# Delete a scan
acuscanner --del-scan SCAN_ID
```

### Vulnerabilities

```bash
# List vulnerabilities for a scan
acuscanner --scan-vulns SCAN_ID --limit 50

# Get full details on a vulnerability
acuscanner --vuln-details SCAN_ID RESULT_ID VULN_ID

# Export to JSON
acuscanner --export-vulns SCAN_ID -o vulnerabilities.json

# Export to CSV
acuscanner --export-vulns SCAN_ID -o vulnerabilities.csv
```

### Reports

```bash
# List report templates
acuscanner --list-report-templates

# Generate a report (waits for completion)
acuscanner --generate-report SCAN_ID --template developer

# Generate and auto-download
acuscanner --generate-report SCAN_ID --template executive --auto-download

# Batch generate for multiple scans
acuscanner --batch-report "SCAN_ID1,SCAN_ID2,SCAN_ID3" --template owasp

# Batch from file
acuscanner --batch-report scan_ids.txt --template pci --auto-download

# List generated reports
acuscanner --list-reports

# Download a specific report
acuscanner --download-report REPORT_ID -o audit_report.pdf

# Delete a report
acuscanner --del-report REPORT_ID
```

Available template names: `developer`, `executive`, `quick`, `hipaa`, `owasp`, `pci`, `iso_27001`, `affected_items` (or use `--template-id UUID` for custom templates).

### Target Management

```bash
# List all targets
acuscanner --list-targets

# Delete a target
acuscanner --del-target TARGET_ID

# Update target properties
acuscanner --update-target TARGET_ID --description "Production API" --criticality 30
```

### Target Groups

```bash
# List groups
acuscanner --list-groups

# Create a group
acuscanner --create-group "Production Servers" --description "All prod web servers"

# Add targets to group
acuscanner --add-to-group GROUP_ID "TARGET_ID1,TARGET_ID2"

# Delete a group
acuscanner --del-group GROUP_ID
```

### Scanning Profiles

```bash
acuscanner --list-profiles
```

### Users (Admin Only)

```bash
# List all users on the Acunetix instance
acuscanner --users
```

### Dashboard & Statistics

```bash
acuscanner --stats
```

Displays a rich boxed dashboard with:
- Total targets, scans, running/completed/failed counts
- Aggregated vulnerability summary by severity
- Current profile and server info

---

## Output Formats

Every list command supports `--format table|json|csv`:

```bash
# JSON (for piping to jq or other tools)
acuscanner --list-scans --format json | jq '.[].scan_id'

# CSV (for spreadsheets)
acuscanner --list-targets --format csv > targets.csv

# Table (default, human-readable with colors)
acuscanner --scan-vulns SCAN_ID --format table
```

---

## Full Command Reference

### Configuration & Profiles

| Command | Description |
|---------|-------------|
| `--setup` | Interactive config wizard (default profile) |
| `--test-connection` | Test API connection & authentication |
| `--whoami` | Show current user identity & active profile |
| `--add-profile NAME` | Create a new named configuration profile |
| `--list-profiles-config` | List all saved profiles with URLs |
| `--del-profile-config NAME` | Delete a saved profile |
| `--use-profile NAME` | Use a named profile for any command |
| `--users` | List all Acunetix instance users (admin) |

### Scanning

| Command | Description |
|---------|-------------|
| `--scan -u URL` | Start a new vulnerability scan |
| `--bulk-scan FILE` | Bulk scan URLs from a file |
| `--schedule DATETIME` | Schedule scan for future (ISO 8601) |
| `--profile-id UUID` | Use specific scanning profile |
| `--delay N` | Seconds between bulk scans |

### Scan Management

| Command | Description |
|---------|-------------|
| `--list-scans` | List recent scans |
| `--my-scans` | Show only your scans (by profile) |
| `--filter-status STATUS` | Filter by status (processing/completed/failed) |
| `--filter-target URL` | Filter by target URL (substring) |
| `--scan-status SCAN_ID` | Detailed scan status with severity |
| `--watch-scan SCAN_ID` | Live real-time monitoring |
| `--abort-scan SCAN_ID` | Stop a running scan |
| `--del-scan SCAN_ID` | Delete a scan permanently |
| `--scan-results SCAN_ID` | List result sessions |

### Vulnerabilities

| Command | Description |
|---------|-------------|
| `--scan-vulns SCAN_ID` | List vulnerabilities for a scan |
| `--vuln-details SCAN RESULT VULN` | Full vulnerability details |
| `--export-vulns SCAN_ID -o FILE` | Export to JSON/CSV |

### Reports

| Command | Description |
|---------|-------------|
| `--list-report-templates` | Available templates |
| `--generate-report SCAN_ID` | Generate a report |
| `--batch-report IDS_OR_FILE` | Reports for multiple scans |
| `--auto-download` | Auto-download after generation |
| `--download-report REPORT_ID` | Download a report |
| `--list-reports` | List generated reports |
| `--del-report REPORT_ID` | Delete a report |

### Targets & Groups

| Command | Description |
|---------|-------------|
| `--list-targets` | List all targets |
| `--del-target TARGET_ID` | Delete a target |
| `--update-target TARGET_ID` | Update target fields |
| `--list-groups` | List target groups |
| `--create-group NAME` | Create a group |
| `--add-to-group GID TIDS` | Add targets to group |
| `--del-group GROUP_ID` | Delete a group |

### Global Options

| Option | Description |
|--------|-------------|
| `--format table\|json\|csv` | Output format |
| `--limit N` | Max items for lists |
| `-o FILE` | Output file path |
| `--interval N` | Watch poll interval |
| `-v, --verbose` | Verbose output |

---

## Troubleshooting

### Connection Failed

```
[-] Connection FAILED.  Check ACUNETIX_URL and ACUNETIX_API_KEY.
```

1. Verify your URL includes `/api/v1`: `https://10.0.0.1:3443/api/v1`
2. Check your API key in the Acunetix dashboard under Profile → API Key
3. If using `ACUNETIX_VERIFY_SSL=false`, ensure the server is reachable
4. Try: `curl -k -H "X-Auth: YOUR_KEY" https://10.0.0.1:3443/api/v1/me`

### Rate Limited

```
[!] Rate-limited.  Retry 1/3 in 2s …
```

AcuScan CLI automatically retries with exponential backoff. If persistent, increase `--delay` for bulk operations.

### Profile Not Found

```
[-] Profile 'alice' not found.  Available: default, bob
```

Create the profile first: `acuscanner --add-profile alice`

### Both Users See All Scans

**This is expected behavior.** Acunetix is instance-level — all authenticated users share scan data. Use `--my-scans` to filter to scans started from your CLI profile.

### Scans from Web UI Don't Show in `--my-scans`

`--my-scans` only tracks scans started through this CLI tool. Scans started via the Acunetix web dashboard are not tracked locally but will appear in `--list-scans`.

---

## Project Structure

```
acunetix-cli/
├── scanner.py              # Main CLI application (v3.0)
├── install.sh              # Cross-platform installer
├── requirements.txt        # Python dependencies
├── README.md               # This documentation
├── cli/
│   ├── utils.py            # Output formatting & banner
│   └── were/
│       ├── .env            # Default profile config
│       ├── scan_history.json   # Local scan ownership tracker
│       └── profiles/       # Named user profiles
│           ├── alice.env
│           └── bob.env
```

---

## Changelog

### v3.0.0 — Multi-User & Enhanced Reports
- **NEW:** Multi-user named profiles (`--add-profile`, `--use-profile`)
- **NEW:** Scan ownership tracking (`--my-scans`)
- **NEW:** User management (`--whoami`, `--users`)
- **NEW:** Scan filtering (`--filter-status`, `--filter-target`)
- **NEW:** Batch report generation (`--batch-report`)
- **NEW:** Auto-download reports (`--auto-download`)
- **NEW:** Rich dashboard (`--stats`)
- **NEW:** API retry with exponential backoff & rate-limit handling
- **NEW:** Categorised, beautiful `--help` output
- **IMPROVED:** Color-coded status and severity everywhere
- **IMPROVED:** Cross-platform installer (Debian, RHEL, macOS)
- **IMPROVED:** Error messages with actionable guidance

### v2.0.0 — Feature-Rich CLI
- Scans, bulk scans, live watch
- Reports, vulnerabilities, target groups
- JSON/CSV/Table output

---

## License

This project is provided as-is for security professionals.  
Use responsibly and only scan targets you are authorised to test.

---

**Developed by [MrpasswordTz](https://github.com/MrpasswordTz) · Powered by BantuHunters**
