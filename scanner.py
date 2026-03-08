#!/usr/bin/env python3
"""
AcuScan CLI v3.0 - Professional Acunetix Vulnerability Scanner CLI

Multi-user profiles, scan ownership tracking, enhanced reports,
beautiful categorized help, retry with backoff, and team workflows.

Developed by MrpasswordTz | Powered by BantuHunters
"""

# ─── Metadata ───────────────────────────────────────────────
__author__ = "MrpasswordTz"
__project__ = "AcuScan CLI"
__version__ = "3.0.0"

# ─── Imports ────────────────────────────────────────────────
import os
import sys
import time
import json
import csv
import glob
import argparse
import textwrap
import urllib3
import requests
from datetime import datetime
from dotenv import load_dotenv
from cli.utils import (
    print_msg, show_banner, severity_color, status_color, format_filesize,
    RED, GREEN, YELLOW, BLUE, CYAN, GRAY, BOLD, RESET, DIM,
)
from cli.were.creds import get_public_url, get_public_key

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Paths ──────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.realpath(__file__))
CONFIG_DIR   = os.path.join(SCRIPT_DIR, "cli", "were")
PROFILES_DIR = os.path.join(CONFIG_DIR, "profiles")
DEFAULT_ENV  = os.path.join(CONFIG_DIR, ".env")
HISTORY_FILE = os.path.join(CONFIG_DIR, "scan_history.json")

os.makedirs(PROFILES_DIR, exist_ok=True)

# ─── Built-in Public Credentials ────────────────────────────
# Loaded from cli/were/creds.py — NOT stored in this file.
# This Acunetix instance is provided FREE by MrpasswordTz.
# Advanced users can override with their own server via --setup.
_BUILTIN_URL = get_public_url()
_BUILTIN_KEY = get_public_key()

# ─── Runtime Globals (set by load_profile) ──────────────────
BASE_URL = None
API_KEY = None
VERIFY_SSL = False
REQUEST_TIMEOUT = 30
CURRENT_PROFILE = "default"
CURRENT_EMAIL = None          # filled lazily on first whoami / my-scans
DEFAULT_SCAN_PROFILE = "11111111-1111-1111-1111-111111111111"
MAX_RETRIES = 3


# ═══════════════════════════════════════════════════════════
#  SECTION 1 ─ PROFILE & CONFIGURATION MANAGEMENT
# ═══════════════════════════════════════════════════════════

def load_profile(profile_name=None):
    """
    Load configuration from a named profile, the default .env,
    or fall back to the built-in public credentials so the tool
    works instantly for everyone without any setup.
    """
    global BASE_URL, API_KEY, VERIFY_SSL, REQUEST_TIMEOUT, CURRENT_PROFILE

    if profile_name and profile_name != "default":
        env_path = os.path.join(PROFILES_DIR, f"{profile_name}.env")
        if not os.path.exists(env_path):
            avail = ", ".join(get_profile_names())
            print_msg(f"Profile '{profile_name}' not found.  Available: {avail}", "error")
            sys.exit(1)
        CURRENT_PROFILE = profile_name
        load_dotenv(env_path, override=True)
    elif os.path.exists(DEFAULT_ENV):
        CURRENT_PROFILE = "default"
        load_dotenv(DEFAULT_ENV, override=True)
    else:
        # No .env at all — first-time user, use built-in public server
        CURRENT_PROFILE = "public"

    BASE_URL        = os.getenv("ACUNETIX_URL")       or _BUILTIN_URL
    API_KEY         = os.getenv("ACUNETIX_API_KEY")    or _BUILTIN_KEY
    VERIFY_SSL      = os.getenv("ACUNETIX_VERIFY_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
    REQUEST_TIMEOUT = int(os.getenv("ACUNETIX_TIMEOUT", "30"))


def get_profile_names():
    """Return sorted list of available profile names."""
    profiles = []
    if os.path.exists(DEFAULT_ENV):
        profiles.append("default")
    for f in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.env"))):
        profiles.append(os.path.basename(f).replace(".env", ""))
    return profiles


def validate_config():
    """Verify config is loaded. Built-in credentials always provide a fallback."""
    # Built-in credentials fill any gaps, so this should never fail.
    # But if someone clears the globals manually, catch it.
    if not BASE_URL or not API_KEY:
        print_msg("Configuration error — falling back to built-in public server.", "warn")
    if CURRENT_PROFILE == "public":
        print_msg(f"Using {BOLD}FREE public server{RESET} provided by MrpasswordTz.", "info")
        print_msg(f"To use your own server:  acuscanner --setup", "info")


# ── Interactive wizards ─────────────────────────────────────

def setup_config():
    """Interactive configuration wizard for the default profile."""
    print(f"\n{BOLD}=== AcuScan CLI — Default Profile Setup ==={RESET}\n")
    url       = input("  Acunetix URL  (e.g. https://10.0.0.1:3443/api/v1): ").strip()
    api_key   = input("  API Key: ").strip()
    verify    = input("  Verify SSL? (yes/no) [no]: ").strip().lower()
    verify    = "true" if verify in {"yes", "y", "true", "1"} else "false"
    timeout   = input("  Request timeout in seconds [30]: ").strip()
    timeout   = timeout if timeout.isdigit() else "30"

    os.makedirs(os.path.dirname(DEFAULT_ENV), exist_ok=True)
    with open(DEFAULT_ENV, "w") as f:
        f.write(f"ACUNETIX_URL={url}\nACUNETIX_API_KEY={api_key}\n"
                f"ACUNETIX_VERIFY_SSL={verify}\nACUNETIX_TIMEOUT={timeout}\n")

    print_msg(f"Saved to {DEFAULT_ENV}", "success")
    print_msg("Verify with:  acuscanner --test-connection", "info")


def add_profile(name):
    """Create a new named profile interactively."""
    env_path = os.path.join(PROFILES_DIR, f"{name}.env")
    if os.path.exists(env_path):
        print_msg(f"Profile '{name}' already exists.", "warn")
        if input("  Overwrite? (y/n) [n]: ").strip().lower() != "y":
            return

    print(f"\n{BOLD}=== Creating Profile: {name} ==={RESET}\n")
    url       = input("  Acunetix URL: ").strip()
    api_key   = input("  API Key: ").strip()
    verify    = input("  Verify SSL? (yes/no) [no]: ").strip().lower()
    verify    = "true" if verify in {"yes", "y", "true", "1"} else "false"
    timeout   = input("  Timeout [30]: ").strip()
    timeout   = timeout if timeout.isdigit() else "30"

    with open(env_path, "w") as f:
        f.write(f"ACUNETIX_URL={url}\nACUNETIX_API_KEY={api_key}\n"
                f"ACUNETIX_VERIFY_SSL={verify}\nACUNETIX_TIMEOUT={timeout}\n")

    print_msg(f"Profile '{name}' saved.", "success")
    print_msg(f"Use:  acuscanner --use-profile {name} --test-connection", "info")


def delete_profile(name):
    """Delete a named profile."""
    if name == "default":
        print_msg("Cannot delete the default profile.  Edit it with --setup instead.", "error")
        return
    env_path = os.path.join(PROFILES_DIR, f"{name}.env")
    if not os.path.exists(env_path):
        print_msg(f"Profile '{name}' does not exist.", "error")
        return
    os.remove(env_path)
    print_msg(f"Profile '{name}' deleted.", "success")


def list_profiles_config():
    """Show all saved configuration profiles in a table."""
    names = get_profile_names()

    print(f"\n  {'Profile':<20} | {'Server URL':<55} | {'Status'}")
    print("  " + "─" * 90)

    # Always show the built-in public server first
    pub_active = f" {GREEN}<-- active{RESET}" if CURRENT_PROFILE == "public" else ""
    print(f"  {CYAN}{'public (built-in)':<20}{RESET} | {_BUILTIN_URL:<55} | {pub_active}")

    for name in names:
        path = DEFAULT_ENV if name == "default" else os.path.join(PROFILES_DIR, f"{name}.env")
        url = "N/A"
        try:
            with open(path) as fh:
                for line in fh:
                    if line.startswith("ACUNETIX_URL="):
                        url = line.split("=", 1)[1].strip()
                        break
        except OSError:
            pass
        active = f" {GREEN}<-- active{RESET}" if name == CURRENT_PROFILE else ""
        print(f"  {name:<20} | {url:<55} | {active}")

    if not names:
        print(f"\n  {DIM}No custom profiles.  Using built-in public server.{RESET}")
        print(f"  {DIM}Run --setup to connect your own Acunetix instance.{RESET}")


# ═══════════════════════════════════════════════════════════
#  SECTION 2 ─ SCAN HISTORY TRACKER  (local ownership DB)
# ═══════════════════════════════════════════════════════════

def _load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_history(data):
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        print_msg(f"Warning – could not write scan history: {e}", "warn")


def _track_scan(scan_id, target_url, email=None):
    """Record a scan in local history for ownership tracking."""
    h = _load_history()
    h[scan_id] = {
        "profile": CURRENT_PROFILE,
        "email":   email or _resolve_email(),
        "target":  target_url,
        "started": datetime.now().isoformat(),
    }
    _save_history(h)


def _get_scan_owner(scan_id):
    """Return (profile, email) for a locally-tracked scan."""
    entry = _load_history().get(scan_id, {})
    return entry.get("profile", ""), entry.get("email", "")


def _resolve_email():
    """Lazy-fetch current user email and cache it."""
    global CURRENT_EMAIL
    if CURRENT_EMAIL is not None:
        return CURRENT_EMAIL
    data = api_request("GET", "/me", retries=1)
    if data:
        CURRENT_EMAIL = data.get("email", "")
    else:
        CURRENT_EMAIL = ""
    return CURRENT_EMAIL


# ═══════════════════════════════════════════════════════════
#  SECTION 3 ─ API LAYER  (retry + backoff)
# ═══════════════════════════════════════════════════════════

def build_headers():
    return {"X-Auth": API_KEY, "Content-Type": "application/json", "Accept": "application/json"}


def api_request(method, endpoint, stream=False, retries=None, **kwargs):
    """HTTP request with automatic retry, backoff, and rate-limit handling."""
    if retries is None:
        retries = MAX_RETRIES
    base = BASE_URL.rstrip("/")
    url  = f"{base}{endpoint}"
    last_exc = None

    for attempt in range(retries + 1):
        try:
            resp = requests.request(
                method=method, url=url, headers=build_headers(),
                verify=VERIFY_SSL, timeout=REQUEST_TIMEOUT,
                stream=stream, **kwargs,
            )

            # ── Rate-limited ──
            if resp.status_code == 429:
                if attempt < retries:
                    wait = min(2 ** attempt * 2, 30)
                    print_msg(f"Rate-limited.  Retry {attempt+1}/{retries} in {wait}s …", "warn")
                    time.sleep(wait)
                    continue

            # ── Server errors ──
            if resp.status_code >= 500 and attempt < retries:
                time.sleep(min(2 ** attempt, 10))
                continue

            # ── Client errors ──
            if resp.status_code >= 400:
                try:
                    body = resp.json()
                    detail = body.get("message") or body.get("details") or body
                except ValueError:
                    detail = resp.text.strip() or "Unknown error"
                print_msg(f"API {resp.status_code} {method} {endpoint}: {detail}", "error")
                return None

            if resp.status_code == 204:
                return {}
            if stream:
                return resp
            return resp.json() if resp.text.strip() else {}

        except requests.exceptions.ConnectionError as e:
            last_exc = e
            if attempt < retries:
                wait = min(2 ** attempt, 10)
                print_msg(f"Connection error.  Retry {attempt+1}/{retries} in {wait}s …", "warn")
                time.sleep(wait)
                continue

        except requests.exceptions.Timeout as e:
            last_exc = e
            if attempt < retries:
                wait = min(2 ** attempt, 10)
                print_msg(f"Timeout.  Retry {attempt+1}/{retries} in {wait}s …", "warn")
                time.sleep(wait)
                continue

        except requests.exceptions.RequestException as e:
            print_msg(f"Request failed: {e}", "error")
            return None

    print_msg(f"All {retries+1} attempts failed: {last_exc}", "error")
    return None


# ═══════════════════════════════════════════════════════════
#  SECTION 4 ─ USER MANAGEMENT
# ═══════════════════════════════════════════════════════════

def whoami():
    """Show the currently authenticated user and active profile."""
    data = api_request("GET", "/me")
    if data is None:
        print_msg("Could not retrieve user info.", "error")
        return None

    is_public = (CURRENT_PROFILE == "public")
    pub_badge = f"  {GREEN}{BOLD}[FREE PUBLIC SERVER]{RESET}" if is_public else ""

    print(f"\n{BOLD}=== Current Identity ==={RESET}{pub_badge}")
    print(f"  Profile:     {CYAN}{CURRENT_PROFILE}{RESET}")
    print(f"  Email:       {data.get('email', 'N/A')}")
    print(f"  User ID:     {data.get('user_id', 'N/A')}")
    print(f"  Role:        {data.get('role', 'N/A')}")
    print(f"  API Server:  {BASE_URL}")
    print(f"  SSL Verify:  {VERIFY_SSL}")
    if is_public:
        print(f"\n  {DIM}This is a free public Acunetix instance shared by MrpasswordTz.{RESET}")
        print(f"  {DIM}To connect your own server:  acuscanner --setup{RESET}")
    return data


def test_connection():
    """Test API connection and authentication."""
    is_public = (CURRENT_PROFILE == "public")
    label = f"{GREEN}public server{RESET}" if is_public else f"profile: {CURRENT_PROFILE}"
    print_msg(f"Testing connection ({label}) …")
    data = api_request("GET", "/me", retries=1)
    if data is None:
        print_msg("Connection FAILED.  Check ACUNETIX_URL and ACUNETIX_API_KEY.", "error")
        return False

    print_msg("Connection successful!", "success")
    print(f"  Profile:  {CURRENT_PROFILE}")
    print(f"  User:     {data.get('email', 'N/A')}")
    print(f"  Role:     {data.get('role', 'N/A')}")
    print(f"  Server:   {BASE_URL}")
    if is_public:
        print(f"  {GREEN}{BOLD}>> FREE public server by MrpasswordTz <<{RESET}")
    return True


def list_users(output_format="table"):
    """List all users on the Acunetix instance (admin privilege required)."""
    data = api_request("GET", "/users")
    if data is None:
        print_msg("Could not list users.  Admin privileges may be required.", "error")
        return

    users = data.get("users", [])
    if not users:
        print_msg("No users found on this instance.", "warn")
        return

    if output_format == "json":
        print(json.dumps(users, indent=2))
        return

    print(f"\n{'User ID':<40} | {'Email':<35} | {'Role':<12} | {'Enabled'}")
    print("─" * 100)
    for u in users:
        enabled = f"{GREEN}Yes{RESET}" if u.get("enabled") else f"{RED}No{RESET}"
        print(f"  {u.get('user_id',''):<38} | {u.get('email',''):<35} | {u.get('role','N/A'):<12} | {enabled}")


# ═══════════════════════════════════════════════════════════
#  SECTION 5 ─ TARGETS
# ═══════════════════════════════════════════════════════════

def get_target_by_address(url):
    data = api_request("GET", "/targets")
    if not data:
        return None
    for t in data.get("targets", []):
        if t.get("address") == url:
            return t
    return None


def list_targets(output_format="table", limit=100):
    data = api_request("GET", f"/targets?l={limit}")
    if data is None:
        return

    targets = data.get("targets", [])
    if not targets:
        print_msg("No targets found.", "warn")
        return

    if output_format == "json":
        print(json.dumps(targets, indent=2))
        return
    if output_format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["target_id", "address", "description", "criticality"])
        for t in targets:
            w.writerow([t.get("target_id",""), t.get("address",""),
                        t.get("description",""), t.get("criticality","")])
        return

    print(f"\n  {'Target ID':<40} | {'Address':<50} | {'Criticality'}")
    print("  " + "─" * 110)
    for t in targets:
        crit = t.get("criticality", "N/A")
        crit_str = f"{RED}{crit}{RESET}" if crit >= 30 else f"{YELLOW}{crit}{RESET}" if crit >= 20 else str(crit)
        print(f"  {t.get('target_id',''):<40} | {t.get('address',''):<50} | {crit_str}")


def delete_target(target_id):
    if api_request("DELETE", f"/targets/{target_id}") is not None:
        print_msg(f"Target {target_id} deleted.", "success")


def update_target(target_id, description=None, criticality=None):
    payload = {}
    if description:
        payload["description"] = description
    if criticality is not None:
        payload["criticality"] = criticality
    if not payload:
        print_msg("Nothing to update — supply --description and/or --criticality.", "warn")
        return
    if api_request("PATCH", f"/targets/{target_id}", json=payload) is not None:
        print_msg(f"Target {target_id} updated.", "success")


# ═══════════════════════════════════════════════════════════
#  SECTION 6 ─ SCANNING PROFILES
# ═══════════════════════════════════════════════════════════

def list_scan_profiles(output_format="table"):
    data = api_request("GET", "/scanning_profiles")
    if data is None:
        return
    profiles = data.get("scanning_profiles", [])
    if not profiles:
        print_msg("No scanning profiles found.", "warn")
        return

    if output_format == "json":
        print(json.dumps(profiles, indent=2))
        return
    if output_format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["profile_id", "name", "custom"])
        for p in profiles:
            w.writerow([p.get("profile_id",""), p.get("name",""), p.get("custom", False)])
        return

    print(f"\n  {'Profile ID':<40} | {'Name':<40} | {'Custom'}")
    print("  " + "─" * 95)
    for p in profiles:
        custom = f"{CYAN}Yes{RESET}" if p.get("custom") else "No"
        print(f"  {p.get('profile_id',''):<40} | {p.get('name',''):<40} | {custom}")


# ═══════════════════════════════════════════════════════════
#  SECTION 7 ─ SCANS  (start · bulk · status · watch · filter)
# ═══════════════════════════════════════════════════════════

def start_scan(url, profile_id=None, schedule_date=None):
    """Start a new scan, reuse existing target if found."""
    profile_id = profile_id or DEFAULT_SCAN_PROFILE
    print_msg(f"Preparing target: {url} …")

    existing = get_target_by_address(url)
    if existing:
        target_id = existing["target_id"]
        print_msg(f"Reusing target: {target_id}", "info")
    else:
        resp = api_request("POST", "/targets", json={
            "address": url,
            "description": f"Added by {CURRENT_PROFILE} via AcuScan CLI",
            "criticality": 10,
        })
        if resp is None:
            return None
        target_id = resp.get("target_id")

    if not target_id:
        print_msg("Unable to resolve target_id.", "error")
        return None

    schedule = {"disable": False, "start_date": None, "time_sensitive": False}
    if schedule_date:
        schedule["start_date"] = schedule_date
        print_msg(f"Scheduled for: {schedule_date}", "info")

    resp = api_request("POST", "/scans", json={
        "target_id":  target_id,
        "profile_id": profile_id,
        "schedule":   schedule,
    })
    if resp is None:
        return None

    scan_id = resp.get("scan_id")
    if not scan_id:
        print_msg("Scan created but no scan_id returned.  Use --list-scans.", "warn")
        return None

    # Track ownership locally
    _track_scan(scan_id, url)

    print_msg(f"Scan started for {url}", "success")
    print_msg(f"Scan ID: {scan_id}", "success")
    scan_status(scan_id)
    return scan_id


def bulk_scan(file_path, profile_id=None, delay=5):
    """Start scans for every URL in a file (one per line, # = comment)."""
    if not os.path.exists(file_path):
        print_msg(f"File not found: {file_path}", "error")
        return

    with open(file_path) as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not urls:
        print_msg("No URLs in file.", "warn")
        return

    print_msg(f"Bulk scan: {len(urls)} URLs, delay {delay}s …", "info")
    ok = []
    for i, url in enumerate(urls, 1):
        print(f"\n  [{i}/{len(urls)}] ", end="")
        sid = start_scan(url, profile_id)
        if sid:
            ok.append(sid)
        if i < len(urls) and delay > 0:
            print_msg(f"Next scan in {delay}s …", "info")
            time.sleep(delay)

    print_msg(f"\nBulk complete: {len(ok)}/{len(urls)} scans started.", "success")
    return ok


def list_scans(limit=10, output_format="table",
               filter_status=None, filter_target=None, my_scans=False):
    """List scans with optional filtering by status, target, or ownership."""
    fetch_limit = min(limit * 4, 500)   # over-fetch to allow client-side filtering
    data = api_request("GET", f"/scans?l={fetch_limit}")
    if data is None:
        return

    scans = data.get("scans", [])

    # ── Apply filters ──
    if filter_status:
        scans = [s for s in scans
                 if (s.get("current_session") or {}).get("status", "").lower() == filter_status.lower()]

    if filter_target:
        ft = filter_target.lower()
        scans = [s for s in scans
                 if ft in (s.get("target") or {}).get("address", "").lower()]

    if my_scans:
        my_email = _resolve_email()
        history  = _load_history()
        scans = [s for s in scans
                 if history.get(s.get("scan_id", ""), {}).get("profile") == CURRENT_PROFILE
                 or history.get(s.get("scan_id", ""), {}).get("email") == my_email]

    scans = scans[:limit]

    if not scans:
        print_msg("No scans match the criteria.", "warn")
        return

    # ── Output ──
    if output_format == "json":
        print(json.dumps(scans, indent=2))
        return

    if output_format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["scan_id", "status", "progress", "target", "profile_name", "started_by"])
        for s in scans:
            cur = s.get("current_session") or {}
            tgt = s.get("target") or {}
            _, email = _get_scan_owner(s.get("scan_id", ""))
            w.writerow([s.get("scan_id",""), cur.get("status",""),
                        cur.get("progress",0), tgt.get("address",""),
                        s.get("profile_name",""), email or "—"])
        return

    # Table
    history = _load_history()
    print(f"\n  {'Scan ID':<40} | {'Status':<12} | {'Prog':<6} | {'Target':<38} | {'By'}")
    print("  " + "─" * 118)
    for scan in scans:
        cur      = scan.get("current_session") or {}
        tgt      = scan.get("target") or {}
        st       = cur.get("status", "unknown")
        progress = cur.get("progress", 0)
        scan_id  = scan.get("scan_id", "")
        prof, email = _get_scan_owner(scan_id)
        who = email or prof or "—"

        st_col = status_color(st)
        # Status column width compensates for ANSI escape codes
        print(f"  {scan_id:<40} | {st_col:<21} | {progress}%{'':<3} | {tgt.get('address',''):<38} | {who}")


def scan_status(scan_id, include_vulns=True):
    """Display detailed status for a single scan."""
    data = api_request("GET", f"/scans/{scan_id}")
    if data is None:
        return

    cur = data.get("current_session") or {}
    sev = cur.get("severity_counts") or {}
    tgt = data.get("target") or {}
    st  = cur.get("status", "unknown")
    prog = cur.get("progress", 0)
    prof, email = _get_scan_owner(scan_id)

    print(f"\n{BOLD}=== Scan Status ==={RESET}")
    print(f"  Scan ID:      {scan_id}")
    print(f"  Target:       {tgt.get('address', 'N/A')}")
    print(f"  Profile:      {data.get('profile_name', data.get('profile_id', 'N/A'))}")
    print(f"  Started By:   {email or prof or '—'}")
    print(f"  Status:       {status_color(st)}")

    prog_str = f"{prog}%"
    if prog == 0 and st == "processing":
        prog_str += "  (initialising …)"
    print(f"  Progress:     {prog_str}")
    print(f"  Session ID:   {cur.get('scan_session_id', 'N/A')}")

    print(f"\n  {BOLD}Severity Counts{RESET}")
    print(f"    {RED}Critical:{RESET}   {sev.get('critical', 0)}")
    print(f"    {YELLOW}High:{RESET}       {sev.get('high', 0)}")
    print(f"    {BLUE}Medium:{RESET}     {sev.get('medium', 0)}")
    print(f"    {GREEN}Low:{RESET}        {sev.get('low', 0)}")
    print(f"    {CYAN}Info:{RESET}       {sev.get('info', 0)}")

    if include_vulns and any(sev.get(k, 0) > 0 for k in ("critical", "high", "medium")):
        print(f"\n  {BOLD}── Latest Vulnerabilities ──{RESET}")
        list_scan_vulnerabilities(scan_id, limit=5, silent=True)


def watch_scan(scan_id, interval=15):
    """Live-watch a scan with real-time vulnerability alerts."""
    print_msg(f"Watching scan {scan_id} every {interval}s — Ctrl+C to stop.")
    last_total = -1
    try:
        while True:
            data = api_request("GET", f"/scans/{scan_id}", retries=1)
            if data is None:
                time.sleep(interval)
                continue

            cur  = data.get("current_session") or {}
            st   = cur.get("status", "unknown")
            prog = cur.get("progress", 0)
            sev  = cur.get("severity_counts") or {}
            total = sum(sev.values())

            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.write(
                f"  [{status_color(st)}] "
                f"Prog: {GREEN}{prog}%{RESET} | "
                f"{RED}C:{sev.get('critical',0)}{RESET} "
                f"{YELLOW}H:{sev.get('high',0)}{RESET} "
                f"{BLUE}M:{sev.get('medium',0)}{RESET} "
                f"{GREEN}L:{sev.get('low',0)}{RESET} "
                f"{CYAN}I:{sev.get('info',0)}{RESET}"
            )
            sys.stdout.flush()

            if total > last_total and last_total != -1:
                diff = total - last_total
                print(f"\n  {GREEN}[+] {diff} new vulnerability{'s' if diff > 1 else ''} detected!{RESET}")
                list_scan_vulnerabilities(scan_id, limit=3, silent=True)
                print("  " + "─" * 50)

            last_total = total

            if st in {"completed", "failed", "aborting", "aborted"}:
                print(f"\n\n  Scan finished: {status_color(st)}")
                scan_status(scan_id)
                return

            time.sleep(max(3, interval))
    except KeyboardInterrupt:
        print("\n  Stopped watching.")


def _check_scan_ownership(scan_id, action="modify"):
    """
    Privacy guard — warn if acting on another user's scan.
    On the public server everyone shares the instance, so we
    block destructive actions on scans you didn't start.
    Returns True if allowed, False if blocked.
    """
    prof, owner_email = _get_scan_owner(scan_id)
    # If we have no local record, it was started by another user or via the web UI
    if not prof and not owner_email:
        print_msg(f"Scan {scan_id} was not started from your CLI.", "warn")
        print_msg("It may belong to another user or was started from the web UI.", "warn")
        confirm = input(f"  Proceed to {action} anyway? (y/n) [n]: ").strip().lower()
        if confirm != "y":
            print_msg(f"Cancelled.", "info")
            return False
        return True
    # If tracked, check if it belongs to current profile
    if prof != CURRENT_PROFILE:
        print_msg(f"This scan belongs to profile '{prof}' ({owner_email}).", "warn")
        print_msg(f"You are using profile '{CURRENT_PROFILE}'.", "warn")
        confirm = input(f"  Proceed to {action} anyway? (y/n) [n]: ").strip().lower()
        if confirm != "y":
            print_msg(f"Cancelled.", "info")
            return False
    return True


def abort_scan(scan_id):
    """Abort a running scan with ownership check."""
    if not _check_scan_ownership(scan_id, action="abort"):
        return
    if api_request("POST", f"/scans/{scan_id}/abort") is not None:
        print_msg(f"Abort requested for {scan_id}.", "success")


def delete_scan(scan_id):
    """Delete a scan with ownership check."""
    if not _check_scan_ownership(scan_id, action="delete"):
        return
    if api_request("DELETE", f"/scans/{scan_id}") is not None:
        # Also remove from local history
        h = _load_history()
        h.pop(scan_id, None)
        _save_history(h)
        print_msg(f"Scan {scan_id} deleted.", "success")


# ═══════════════════════════════════════════════════════════
#  SECTION 8 ─ SCAN RESULTS & VULNERABILITIES
# ═══════════════════════════════════════════════════════════

def list_scan_results(scan_id):
    data = api_request("GET", f"/scans/{scan_id}/results")
    if data is None:
        return
    results = data.get("results", [])
    if not results:
        print_msg("No results yet — scan may still be running.", "warn")
        return

    print(f"\n  {'Result ID':<40} | {'Status':<12} | {'Start':<22} | {'End'}")
    print("  " + "─" * 120)
    for r in results:
        print(f"  {r.get('result_id',''):<40} | {r.get('status',''):<12} | "
              f"{r.get('start_date','N/A'):<22} | {r.get('end_date','N/A')}")


def get_latest_result_id(scan_id):
    data = api_request("GET", f"/scans/{scan_id}/results")
    if not data:
        return None
    results = data.get("results", [])
    return results[0].get("result_id") if results else None


def list_scan_vulnerabilities(scan_id, result_id=None, limit=20,
                              silent=False, output_format="table"):
    if not result_id:
        result_id = get_latest_result_id(scan_id)
        if not result_id:
            if not silent:
                print_msg("No scan result available yet.", "warn")
            return
        if not silent:
            print_msg(f"Using latest result: {result_id}")

    data = api_request("GET",
        f"/scans/{scan_id}/results/{result_id}/vulnerabilities?l={limit}")
    if data is None:
        return

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        if not silent:
            print_msg("No vulnerabilities found — target may be clean.", "success")
        return vulns

    if output_format == "json":
        print(json.dumps(vulns, indent=2))
        return vulns
    if output_format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["severity", "vuln_id", "vt_name", "affects_url"])
        for v in vulns:
            w.writerow([v.get("severity",0), v.get("vuln_id",""),
                        v.get("vt_name",""), v.get("affects_url","")])
        return vulns

    if not silent:
        print(f"\n  Showing up to {limit} vulnerabilities\n")

    print(f"  {'Severity':<18} | {'Vuln ID':<40} | {'Name'}")
    print("  " + "─" * 110)
    for v in vulns:
        sev = severity_color(v.get("severity", 0))
        print(f"  {sev:<27} | {v.get('vuln_id',''):<40} | {v.get('vt_name','N/A')}")

    return vulns


def get_vulnerability_details(scan_id, result_id, vuln_id):
    """Show detailed info about a specific vulnerability."""
    data = api_request("GET",
        f"/scans/{scan_id}/results/{result_id}/vulnerabilities/{vuln_id}")
    if data is None:
        return

    print(f"\n{BOLD}=== Vulnerability Details ==={RESET}")
    print(f"  Name:        {data.get('vt_name', 'N/A')}")
    print(f"  Severity:    {severity_color(data.get('severity', 0))}")
    print(f"  Affects:     {data.get('affects_url', 'N/A')}")
    print(f"  Status:      {data.get('status', 'N/A')}")
    print(f"  CVSS Score:  {data.get('cvss_score', 'N/A')}")

    if data.get("description"):
        print(f"\n  {BOLD}Description{RESET}\n  {data['description']}")
    if data.get("impact"):
        print(f"\n  {BOLD}Impact{RESET}\n  {data['impact']}")
    if data.get("recommendation"):
        print(f"\n  {BOLD}Recommendation{RESET}\n  {data['recommendation']}")
    if data.get("request"):
        print(f"\n  {BOLD}HTTP Request{RESET}\n  {data['request']}")
    if data.get("response_info"):
        print(f"\n  {BOLD}Response Info{RESET}\n  {data['response_info']}")

    return data


def export_vulnerabilities(scan_id, output_file, result_id=None):
    """Export all vulnerabilities to JSON or CSV file."""
    if not result_id:
        result_id = get_latest_result_id(scan_id)
        if not result_id:
            print_msg("No scan result available.", "error")
            return

    data = api_request("GET",
        f"/scans/{scan_id}/results/{result_id}/vulnerabilities?l=10000")
    if data is None:
        return

    vulns = data.get("vulnerabilities", [])
    ext = os.path.splitext(output_file)[1].lower()

    if ext == ".csv":
        with open(output_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["severity", "vuln_id", "vt_name", "affects_url", "status", "cvss_score"])
            for v in vulns:
                w.writerow([v.get("severity",""), v.get("vuln_id",""),
                            v.get("vt_name",""), v.get("affects_url",""),
                            v.get("status",""), v.get("cvss_score","")])
    else:
        with open(output_file, "w") as f:
            json.dump(vulns, f, indent=2)

    print_msg(f"Exported {len(vulns)} vulnerabilities → {output_file}", "success")


# ═══════════════════════════════════════════════════════════
#  SECTION 9 ─ REPORTS  (templates · generate · batch · download)
# ═══════════════════════════════════════════════════════════

def list_report_templates(output_format="table"):
    data = api_request("GET", "/report_templates")
    if data is None:
        return
    templates = data.get("templates", [])
    if not templates:
        print_msg("No report templates found.", "warn")
        return

    if output_format == "json":
        print(json.dumps(templates, indent=2))
        return

    print(f"\n  {'Template ID':<40} | {'Name':<40} | {'Group'}")
    print("  " + "─" * 100)
    for t in templates:
        print(f"  {t.get('template_id',''):<40} | {t.get('name',''):<40} | {t.get('group','N/A')}")
    return templates


def list_reports(limit=20, output_format="table"):
    data = api_request("GET", f"/reports?l={limit}")
    if data is None:
        return
    reports = data.get("reports", [])
    if not reports:
        print_msg("No reports found.", "warn")
        return

    if output_format == "json":
        print(json.dumps(reports, indent=2))
        return

    print(f"\n  {'Report ID':<40} | {'Status':<12} | {'Template':<28} | {'Generated'}")
    print("  " + "─" * 130)
    for r in reports:
        st = status_color(r.get("status", "unknown"))
        print(f"  {r.get('report_id',''):<40} | {st:<21} | "
              f"{r.get('template_name','N/A'):<28} | {r.get('generation_date','N/A')}")


def _resolve_template_id(template_name=None, template_id=None):
    """Return a template UUID — resolve by friendly name if needed."""
    if template_id:
        return template_id

    name = (template_name or "developer").lower()
    templates_data = api_request("GET", "/report_templates")
    if not templates_data:
        return None

    for t in templates_data.get("templates", []):
        if name in t.get("name", "").lower():
            print_msg(f"Using template: {t.get('name')}", "info")
            return t.get("template_id")

    print_msg(f"Template '{name}' not found.  Use --list-report-templates.", "error")
    return None


def generate_report(scan_id, template_id=None, template_name="developer",
                    auto_download=False, output_dir="."):
    """Generate a report for a scan, optionally auto-downloading it."""
    tid = _resolve_template_id(template_name, template_id)
    if not tid:
        return None

    resp = api_request("POST", "/reports", json={
        "template_id": tid,
        "source": {"list_type": "scans", "id_list": [scan_id]},
    })
    if resp is None:
        return None

    report_id = resp.get("report_id")
    print_msg(f"Report generation started — ID: {report_id}", "success")

    # Wait for completion (up to 5 min)
    print_msg("Waiting for report …", "info")
    for _ in range(60):
        time.sleep(5)
        rd = api_request("GET", f"/reports/{report_id}", retries=1)
        if not rd:
            continue
        st = rd.get("status", "")
        if st == "completed":
            print_msg("Report ready!", "success")
            if auto_download:
                out = os.path.join(output_dir, f"report_{report_id}.pdf")
                download_report(report_id, out)
            else:
                dl = rd.get("download", [])
                if dl:
                    print_msg(f"Download with:  acuscanner --download-report {report_id}", "info")
            return rd
        elif st == "failed":
            print_msg("Report generation failed.", "error")
            return None
        sys.stdout.write(".")
        sys.stdout.flush()

    print_msg("\nReport generation timed out after 5 min.", "warn")
    return resp


def batch_report(file_or_ids, template_name="developer", template_id=None,
                 auto_download=False, output_dir="."):
    """Generate reports for multiple scans (comma-separated IDs or a file)."""
    # Determine scan IDs
    if os.path.isfile(file_or_ids):
        with open(file_or_ids) as f:
            scan_ids = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        scan_ids = [s.strip() for s in file_or_ids.split(",") if s.strip()]

    if not scan_ids:
        print_msg("No scan IDs provided.", "warn")
        return

    tid = _resolve_template_id(template_name, template_id)
    if not tid:
        return

    print_msg(f"Generating reports for {len(scan_ids)} scans …", "info")
    for i, sid in enumerate(scan_ids, 1):
        print(f"\n  [{i}/{len(scan_ids)}] Scan: {sid}")
        generate_report(sid, template_id=tid, auto_download=auto_download,
                        output_dir=output_dir)


def download_report(report_id, output_path=None):
    """Download a completed report."""
    rd = api_request("GET", f"/reports/{report_id}")
    if rd is None:
        return

    st = rd.get("status", "")
    if st != "completed":
        print_msg(f"Report not ready — status: {st}", "warn")
        return

    links = rd.get("download", [])
    if not links:
        print_msg("No download link available.", "error")
        return

    if not output_path:
        output_path = f"report_{report_id}.pdf"

    link = links[0]
    # Acunetix returns full API paths; strip /api/v1 prefix since BASE_URL includes it
    if link.startswith("/api/v1"):
        link = link[len("/api/v1"):]
    elif not link.startswith("/"):
        link = f"/reports/download/{link}"
    response = api_request("GET", link, stream=True)
    if response is None:
        return

    size = 0
    with open(output_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
            size += len(chunk)

    print_msg(f"Downloaded → {output_path}  ({format_filesize(size)})", "success")


def delete_report(report_id):
    if api_request("DELETE", f"/reports/{report_id}") is not None:
        print_msg(f"Report {report_id} deleted.", "success")


# ═══════════════════════════════════════════════════════════
#  SECTION 10 ─ TARGET GROUPS
# ═══════════════════════════════════════════════════════════

def list_target_groups(output_format="table"):
    data = api_request("GET", "/target_groups")
    if data is None:
        return
    groups = data.get("groups", [])
    if not groups:
        print_msg("No target groups found.", "warn")
        return

    if output_format == "json":
        print(json.dumps(groups, indent=2))
        return

    print(f"\n  {'Group ID':<40} | {'Name':<30} | {'Targets'}")
    print("  " + "─" * 85)
    for g in groups:
        print(f"  {g.get('group_id',''):<40} | {g.get('name',''):<30} | {g.get('target_count', 0)}")


def create_target_group(name, description=""):
    resp = api_request("POST", "/target_groups", json={
        "name": name, "description": description,
    })
    if resp is None:
        return
    gid = resp.get("group_id")
    print_msg(f"Group created — ID: {gid}", "success")
    return gid


def add_targets_to_group(group_id, target_ids):
    resp = api_request("PATCH", f"/target_groups/{group_id}/targets", json={
        "add": target_ids, "remove": [],
    })
    if resp is not None:
        print_msg(f"Added {len(target_ids)} target(s) to group.", "success")


def delete_target_group(group_id):
    if api_request("DELETE", f"/target_groups/{group_id}") is not None:
        print_msg(f"Group {group_id} deleted.", "success")


# ═══════════════════════════════════════════════════════════
#  SECTION 11 ─ STATISTICS & DASHBOARD
# ═══════════════════════════════════════════════════════════

def show_stats():
    """Display a rich dashboard of scanning statistics."""
    tdata = api_request("GET", "/targets")
    sdata = api_request("GET", "/scans?l=200")
    if tdata is None or sdata is None:
        return

    targets = tdata.get("targets", [])
    scans   = sdata.get("scans", [])

    running   = sum(1 for s in scans if (s.get("current_session") or {}).get("status") == "processing")
    completed = sum(1 for s in scans if (s.get("current_session") or {}).get("status") == "completed")
    failed    = sum(1 for s in scans if (s.get("current_session") or {}).get("status") in ("failed", "aborted"))
    scheduled = sum(1 for s in scans if (s.get("current_session") or {}).get("status") == "scheduled")

    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for s in scans:
        sev = (s.get("current_session") or {}).get("severity_counts") or {}
        for k in totals:
            totals[k] += sev.get(k, 0)

    total_vulns = sum(totals.values())

    print(f"\n{BOLD}╔══════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║          AcuScan Dashboard  (v{__version__})           ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║{RESET}  Profile:  {CYAN}{CURRENT_PROFILE:<37}{RESET} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}  Server:   {BASE_URL:<37} {BOLD}║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║{RESET}  {BOLD}Assets & Scans{RESET}                                 {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    Targets:        {len(targets):<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    Total Scans:    {len(scans):<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {YELLOW}Running:{RESET}        {running:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {GREEN}Completed:{RESET}      {completed:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {RED}Failed:{RESET}         {failed:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {CYAN}Scheduled:{RESET}      {scheduled:<28} {BOLD}║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║{RESET}  {BOLD}Vulnerability Summary{RESET}  (total: {total_vulns:<16}) {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {RED}Critical:{RESET}       {totals['critical']:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {YELLOW}High:{RESET}           {totals['high']:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {BLUE}Medium:{RESET}         {totals['medium']:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {GREEN}Low:{RESET}            {totals['low']:<28} {BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}    {CYAN}Info:{RESET}           {totals['info']:<28} {BOLD}║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════╝{RESET}")


# ═══════════════════════════════════════════════════════════
#  SECTION 12 ─ ARGUMENT PARSER  (grouped, categorised help)
# ═══════════════════════════════════════════════════════════

HELP_EPILOG = f"""{BOLD}
─── FREE Public Server ──────────────────────────────────────{RESET}

  {GREEN}This tool comes with a FREE built-in Acunetix server!{RESET}
  No setup needed — just install and scan.  Powered by MrpasswordTz.

  {CYAN}# Works instantly — no API key needed{RESET}
  acuscanner --scan -u https://example.com
  acuscanner --list-scans
  acuscanner --whoami

  {CYAN}# Want to use your OWN Acunetix server instead?{RESET}
  acuscanner --setup

{BOLD}─── Quick Examples ──────────────────────────────────────────{RESET}

  {CYAN}# Scanning{RESET}
  acuscanner --scan -u https://example.com
  acuscanner --scan -u https://example.com --schedule "2026-06-01T09:00:00"
  acuscanner --bulk-scan urls.txt --delay 10

  {CYAN}# Filtering scans{RESET}
  acuscanner --list-scans --filter-status completed
  acuscanner --list-scans --filter-target example.com
  acuscanner --my-scans --limit 50

  {CYAN}# Reports{RESET}
  acuscanner --generate-report SCAN_ID --template developer --auto-download
  acuscanner --batch-report "ID1,ID2,ID3" --template executive
  acuscanner --download-report REPORT_ID -o report.pdf

  {CYAN}# Export & output{RESET}
  acuscanner --list-scans --format json
  acuscanner --export-vulns SCAN_ID -o vulns.csv

  {CYAN}# Multi-user profiles (advanced){RESET}
  acuscanner --add-profile alice
  acuscanner --use-profile alice --scan -u https://target.com
  acuscanner --use-profile bob   --list-scans

{BOLD}─── Multi-User Architecture ─────────────────────────────────{RESET}

  Acunetix is an {BOLD}instance-level{RESET} scanner.  All authenticated users
  on the same server share targets, scans, and reports.

  This means both Alice and Bob can:
    • List the same scans (even those started by the other)
    • Generate reports on each other's scans
    • Abort or delete each other's scans (if their role permits)

  {BOLD}Named profiles{RESET} let each person store their own API key locally,
  so you can quickly switch identities or servers:

    acuscanner --use-profile alice --whoami
    acuscanner --use-profile bob   --my-scans

  The {BOLD}--my-scans{RESET} flag filters to scans started from YOUR profile,
  tracked locally in scan_history.json.

{DIM}  Developed by MrpasswordTz | Powered by BantuHunters{RESET}
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="acuscanner",
        description=(
            f"{BOLD}AcuScan CLI v{__version__}{RESET} — "
            "Professional Acunetix Vulnerability Scanner CLI\n"
            f"  {DIM}Developed by MrpasswordTz  ·  Powered by BantuHunters{RESET}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )

    # ── Global options ──────────────────────────────────────
    global_grp = parser.add_argument_group(
        f"{BOLD}Global Options{RESET}",
        "Options that apply to any command."
    )
    global_grp.add_argument("--use-profile", metavar="NAME",
        help="Use a named configuration profile instead of default")
    global_grp.add_argument("--format", choices=["table","json","csv"], default="table",
        help="Output format (default: table)")
    global_grp.add_argument("--limit", type=int, default=10,
        help="Max items for list commands (default: 10)")
    global_grp.add_argument("-o", "--output", metavar="FILE",
        help="Output file path for exports/downloads")
    global_grp.add_argument("-v", "--verbose", action="store_true",
        help="Verbose output with debug info")

    # ── Configuration & Profiles ────────────────────────────
    config_grp = parser.add_argument_group(
        f"{BOLD}Configuration & Profiles{RESET}",
        "Set up connections and manage multi-user profiles."
    )
    config_grp.add_argument("--setup", action="store_true",
        help="Interactive configuration wizard (default profile)")
    config_grp.add_argument("--test-connection", action="store_true",
        help="Test API connection & authentication")
    config_grp.add_argument("--whoami", action="store_true",
        help="Show current user identity & active profile")
    config_grp.add_argument("--add-profile", metavar="NAME",
        help="Create a new named profile interactively")
    config_grp.add_argument("--list-profiles-config", action="store_true",
        help="List all saved configuration profiles")
    config_grp.add_argument("--del-profile-config", metavar="NAME",
        help="Delete a saved named profile")
    config_grp.add_argument("--users", action="store_true",
        help="List all users on the Acunetix instance (admin)")

    # ── Scanning ────────────────────────────────────────────
    scan_grp = parser.add_argument_group(
        f"{BOLD}Scanning{RESET}",
        "Start and manage vulnerability scans."
    )
    scan_grp.add_argument("--scan", action="store_true",
        help="Start a new scan (requires -u / --url)")
    scan_grp.add_argument("-u", "--url", metavar="URL",
        help="Target URL to scan")
    scan_grp.add_argument("--bulk-scan", metavar="FILE",
        help="Bulk scan URLs from file (one per line)")
    scan_grp.add_argument("--profile-id", metavar="UUID",
        default=DEFAULT_SCAN_PROFILE,
        help="Scanning profile UUID (default: Full Scan)")
    scan_grp.add_argument("--schedule", metavar="DATETIME",
        help="Schedule scan (ISO format: 2026-06-01T09:00:00)")
    scan_grp.add_argument("--delay", type=int, default=5,
        help="Seconds between bulk scans (default: 5)")

    # ── Scan Management ─────────────────────────────────────
    mgmt_grp = parser.add_argument_group(
        f"{BOLD}Scan Management{RESET}",
        "List, filter, watch, abort, and delete scans."
    )
    mgmt_grp.add_argument("--list-scans", action="store_true",
        help="List recent scans")
    mgmt_grp.add_argument("--my-scans", action="store_true",
        help="List only scans started by current profile/user")
    mgmt_grp.add_argument("--filter-status", metavar="STATUS",
        help="Filter scans by status (processing, completed, failed …)")
    mgmt_grp.add_argument("--filter-target", metavar="URL",
        help="Filter scans by target address (substring match)")
    mgmt_grp.add_argument("--scan-status", metavar="SCAN_ID",
        help="Show detailed scan status with severity counts")
    mgmt_grp.add_argument("--watch-scan", metavar="SCAN_ID",
        help="Watch scan progress in real-time")
    mgmt_grp.add_argument("--interval", type=int, default=15,
        help="Watch polling interval in seconds (default: 15)")
    mgmt_grp.add_argument("--abort-scan", metavar="SCAN_ID",
        help="Abort / stop a running scan")
    mgmt_grp.add_argument("--del-scan", metavar="SCAN_ID",
        help="Delete a scan permanently")
    mgmt_grp.add_argument("--scan-results", metavar="SCAN_ID",
        help="List result history for a scan")

    # ── Vulnerabilities ─────────────────────────────────────
    vuln_grp = parser.add_argument_group(
        f"{BOLD}Vulnerabilities{RESET}",
        "Inspect, search, and export vulnerability findings."
    )
    vuln_grp.add_argument("--scan-vulns", metavar="SCAN_ID",
        help="List vulnerabilities for a scan")
    vuln_grp.add_argument("--vuln-details", nargs=3,
        metavar=("SCAN_ID", "RESULT_ID", "VULN_ID"),
        help="Get detailed info about a specific vulnerability")
    vuln_grp.add_argument("--export-vulns", metavar="SCAN_ID",
        help="Export vulnerabilities to JSON/CSV file (-o)")
    vuln_grp.add_argument("--result-id", metavar="UUID",
        help="Specific result UUID (auto-detected if omitted)")

    # ── Reports ─────────────────────────────────────────────
    report_grp = parser.add_argument_group(
        f"{BOLD}Reports{RESET}",
        "Generate, download, and manage PDF/HTML reports."
    )
    report_grp.add_argument("--list-report-templates", action="store_true",
        help="List available report templates")
    report_grp.add_argument("--list-reports", action="store_true",
        help="List generated reports")
    report_grp.add_argument("--generate-report", metavar="SCAN_ID",
        help="Generate a report for a scan")
    report_grp.add_argument("--batch-report", metavar="IDS_OR_FILE",
        help="Generate reports for multiple scans (comma-separated or file)")
    report_grp.add_argument("--template", default="developer",
        help="Report template name (default: developer)")
    report_grp.add_argument("--template-id", metavar="UUID",
        help="Report template UUID (overrides --template)")
    report_grp.add_argument("--auto-download", action="store_true",
        help="Automatically download report after generation")
    report_grp.add_argument("--download-report", metavar="REPORT_ID",
        help="Download a completed report")
    report_grp.add_argument("--del-report", metavar="REPORT_ID",
        help="Delete a report")

    # ── Targets ─────────────────────────────────────────────
    target_grp = parser.add_argument_group(
        f"{BOLD}Target Management{RESET}",
        "List, update, and delete scan targets."
    )
    target_grp.add_argument("--list-targets", action="store_true",
        help="List all targets")
    target_grp.add_argument("--del-target", metavar="TARGET_ID",
        help="Delete a target by ID")
    target_grp.add_argument("--update-target", metavar="TARGET_ID",
        help="Update target properties")
    target_grp.add_argument("--description", metavar="TEXT",
        help="Description for target or group")
    target_grp.add_argument("--criticality", type=int,
        choices=[0, 10, 20, 30],
        help="Target criticality (0=low, 10=normal, 20=high, 30=critical)")

    # ── Target Groups ───────────────────────────────────────
    group_grp = parser.add_argument_group(
        f"{BOLD}Target Groups{RESET}",
        "Organise targets into logical groups."
    )
    group_grp.add_argument("--list-groups", action="store_true",
        help="List target groups")
    group_grp.add_argument("--create-group", metavar="NAME",
        help="Create a new target group")
    group_grp.add_argument("--del-group", metavar="GROUP_ID",
        help="Delete a target group")
    group_grp.add_argument("--add-to-group", nargs=2,
        metavar=("GROUP_ID", "TARGET_IDS"),
        help="Add targets to group (comma-separated IDs)")

    # ── Scanning Profiles ───────────────────────────────────
    profile_grp = parser.add_argument_group(
        f"{BOLD}Scanning Profiles{RESET}",
        "View Acunetix scanning profile types."
    )
    profile_grp.add_argument("--list-profiles", action="store_true",
        help="List available scanning profiles (Full Scan, High Risk, etc.)")

    # ── Statistics ──────────────────────────────────────────
    stats_grp = parser.add_argument_group(
        f"{BOLD}Statistics & Dashboard{RESET}",
        "Overview of your scanning environment."
    )
    stats_grp.add_argument("--stats", action="store_true",
        help="Show rich dashboard with scan & vulnerability summary")

    return parser


# ═══════════════════════════════════════════════════════════
#  SECTION 13 ─ MAIN
# ═══════════════════════════════════════════════════════════

def _count_actions(args):
    """Count how many action flags are set to enforce one-at-a-time."""
    actions = [
        args.setup, args.test_connection, args.whoami,
        bool(args.add_profile), args.list_profiles_config, bool(args.del_profile_config),
        args.users,
        args.scan, bool(args.bulk_scan),
        args.list_scans, args.my_scans, bool(args.scan_status), bool(args.watch_scan),
        bool(args.abort_scan), bool(args.del_scan), bool(args.scan_results),
        bool(args.scan_vulns), bool(args.vuln_details), bool(args.export_vulns),
        args.list_report_templates, args.list_reports,
        bool(args.generate_report), bool(args.batch_report),
        bool(args.download_report), bool(args.del_report),
        args.list_targets, bool(args.del_target), bool(args.update_target),
        args.list_groups, bool(args.create_group), bool(args.del_group),
        bool(args.add_to_group),
        args.list_profiles, args.stats,
    ]
    return sum(1 for a in actions if a)


def main():
    show_banner()
    parser = build_parser()
    args = parser.parse_args()

    # ── Load profile ──
    load_profile(args.use_profile)

    # ── Ensure only one action ──
    if _count_actions(args) > 1:
        print_msg("Please specify only one action at a time.", "error")
        sys.exit(1)

    # ── Configuration (no API key needed) ──
    if args.setup:
        setup_config()
        return
    if args.add_profile:
        add_profile(args.add_profile)
        return
    if args.list_profiles_config:
        list_profiles_config()
        return
    if args.del_profile_config:
        delete_profile(args.del_profile_config)
        return

    # ── Everything else needs valid config ──
    validate_config()

    # Configuration & identity
    if args.test_connection:
        test_connection()
    elif args.whoami:
        whoami()
    elif args.users:
        list_users(output_format=args.format)

    # Scanning
    elif args.scan:
        if not args.url:
            print_msg("--scan requires -u / --url", "error")
            sys.exit(1)
        start_scan(args.url, args.profile_id, args.schedule)
    elif args.bulk_scan:
        bulk_scan(args.bulk_scan, args.profile_id, args.delay)

    # Scan management
    elif args.list_scans:
        list_scans(limit=args.limit, output_format=args.format,
                   filter_status=args.filter_status, filter_target=args.filter_target)
    elif args.my_scans:
        list_scans(limit=args.limit, output_format=args.format, my_scans=True,
                   filter_status=args.filter_status, filter_target=args.filter_target)
    elif args.scan_status:
        scan_status(args.scan_status)
    elif args.watch_scan:
        watch_scan(args.watch_scan, interval=args.interval)
    elif args.abort_scan:
        abort_scan(args.abort_scan)
    elif args.del_scan:
        delete_scan(args.del_scan)
    elif args.scan_results:
        list_scan_results(args.scan_results)

    # Vulnerabilities
    elif args.scan_vulns:
        list_scan_vulnerabilities(args.scan_vulns, result_id=args.result_id,
                                  limit=args.limit, output_format=args.format)
    elif args.vuln_details:
        get_vulnerability_details(*args.vuln_details)
    elif args.export_vulns:
        out = args.output or f"vulns_{args.export_vulns}.json"
        export_vulnerabilities(args.export_vulns, out, args.result_id)

    # Reports
    elif args.list_report_templates:
        list_report_templates(output_format=args.format)
    elif args.list_reports:
        list_reports(limit=args.limit, output_format=args.format)
    elif args.generate_report:
        generate_report(args.generate_report, template_id=args.template_id,
                        template_name=args.template,
                        auto_download=args.auto_download,
                        output_dir=os.path.dirname(args.output) if args.output else ".")
    elif args.batch_report:
        batch_report(args.batch_report, template_name=args.template,
                     template_id=args.template_id,
                     auto_download=args.auto_download,
                     output_dir=os.path.dirname(args.output) if args.output else ".")
    elif args.download_report:
        download_report(args.download_report, args.output)
    elif args.del_report:
        delete_report(args.del_report)

    # Targets
    elif args.list_targets:
        list_targets(output_format=args.format, limit=args.limit)
    elif args.del_target:
        delete_target(args.del_target)
    elif args.update_target:
        update_target(args.update_target, args.description, args.criticality)

    # Target groups
    elif args.list_groups:
        list_target_groups(output_format=args.format)
    elif args.create_group:
        create_target_group(args.create_group, args.description or "")
    elif args.del_group:
        delete_target_group(args.del_group)
    elif args.add_to_group:
        gid, tids = args.add_to_group
        add_targets_to_group(gid, [t.strip() for t in tids.split(",")])

    # Scanning profiles
    elif args.list_profiles:
        list_scan_profiles(output_format=args.format)

    # Stats
    elif args.stats:
        show_stats()

    # No action
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
