#!/usr/bin/env python3
"""AcuScan CLI v3.0 - Utility functions for output formatting and display."""

import sys

# ============== COLOR CODES ==============
RESET   = "\033[0m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
GRAY    = "\033[90m"
BOLD    = "\033[1m"
DIM     = "\033[2m"


def print_msg(message, status="info"):
    """Print a status-prefixed message."""
    prefixes = {
        "info":    f"{BLUE}[*]{RESET}",
        "success": f"{GREEN}[+]{RESET}",
        "error":   f"{RED}[-]{RESET}",
        "warn":    f"{YELLOW}[!]{RESET}",
        "debug":   f"{GRAY}[D]{RESET}",
    }
    prefix = prefixes.get(status, f"{BLUE}[*]{RESET}")
    print(f"{prefix} {message}", file=sys.stderr if status == "error" else sys.stdout)


def severity_color(severity_int):
    """Return colored severity label from Acunetix severity integer."""
    mapping = {
        4: f"{RED}CRITICAL{RESET}",
        3: f"{YELLOW}HIGH{RESET}",
        2: f"{BLUE}MEDIUM{RESET}",
        1: f"{GREEN}LOW{RESET}",
        0: f"{CYAN}INFO{RESET}",
    }
    return mapping.get(severity_int, str(severity_int))


def status_color(status_str):
    """Return colored status label."""
    s = status_str.lower()
    if s == "processing":
        return f"{YELLOW}{status_str}{RESET}"
    elif s == "completed":
        return f"{GREEN}{status_str}{RESET}"
    elif s in ("failed", "aborted"):
        return f"{RED}{status_str}{RESET}"
    elif s == "scheduled":
        return f"{CYAN}{status_str}{RESET}"
    return status_str


def format_filesize(size_bytes):
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def show_banner():
    banner = f"""
    {GREEN}
                                                      
  ▄             ▗▄▖                               
 ▐█▌           ▗▛▀▜                               
 ▐█▌  ▟██▖▐▌ ▐▌▐▙    ▟██▖ ▟██▖▐▙██▖▐▙██▖ ▟█▙  █▟█▌
 █ █ ▐▛  ▘▐▌ ▐▌ ▜█▙ ▐▛  ▘ ▘▄▟▌▐▛ ▐▌▐▛ ▐▌▐▙▄▟▌ █▘  
 ███ ▐▌   ▐▌ ▐▌   ▜▌▐▌   ▗█▀▜▌▐▌ ▐▌▐▌ ▐▌▐▛▀▀▘ █   
▗█ █▖▝█▄▄▌▐▙▄█▌▐▄▄▟▘▝█▄▄▌▐▙▄█▌▐▌ ▐▌▐▌ ▐▌▝█▄▄▌ █   
▝▘ ▝▘ ▝▀▀  ▀▀▝▘ ▀▀▘  ▝▀▀  ▀▀▝▘▝▘ ▝▘▝▘ ▝▘ ▝▀▀  ▀                                                                                                                                                                                                                                                                           
    {RESET}
    {YELLOW}{BOLD}AcuScan CLI v3.0 - Professional Vulnerability Scanner{RESET}
    {GREEN}{BOLD}FREE for everyone — No setup needed, just scan!{RESET}
    {CYAN}Developed By: MrpasswordTz{RESET}
    {GRAY}Powered by: BantuHunters{RESET}
    {DIM}─────────────────────────────────────────────────────{RESET}
    """
    print(banner)
