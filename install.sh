#!/bin/bash
# ─────────────────────────────────────────────────
# AcuScan CLI v3.0 Installer
# Developed by MrpasswordTz | Powered by BantuHunters
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, macOS
# ─────────────────────────────────────────────────

set -e

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

INSTALL_DIR="/opt/acunetix-cli"

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
fail()    { echo -e "${RED}[-]${RESET} $1"; exit 1; }

echo -e "
${GREEN}${BOLD}
                                                                 
  ▄             ▗▄▖                               
 ▐█▌           ▗▛▀▜                               
 ▐█▌  ▟██▖▐▌ ▐▌▐▙    ▟██▖ ▟██▖▐▙██▖▐▙██▖ ▟█▙  █▟█▌
 █ █ ▐▛  ▘▐▌ ▐▌ ▜█▙ ▐▛  ▘ ▘▄▟▌▐▛ ▐▌▐▛ ▐▌▐▙▄▟▌ █▘  
 ███ ▐▌   ▐▌ ▐▌   ▜▌▐▌   ▗█▀▜▌▐▌ ▐▌▐▌ ▐▌▐▛▀▀▘ █   
▗█ █▖▝█▄▄▌▐▙▄█▌▐▄▄▟▘▝█▄▄▌▐▙▄█▌▐▌ ▐▌▐▌ ▐▌▝█▄▄▌ █   
▝▘ ▝▘ ▝▀▀  ▀▀▝▘ ▀▀▘  ▝▀▀  ▀▀▝▘▝▘ ▝▘▝▘ ▝▘ ▝▀▀  ▀                                                                                                                                                                                    
${RESET}
${BOLD}  AcuScan CLI v3.0 — Installer${RESET}
  ${CYAN}Developed by MrpasswordTz | BantuHunters${RESET}
──────────────────────────────────────────────────
"

# Check root
if [ "$EUID" -ne 0 ]; then
    fail "Please run as root:  sudo ./install.sh"
fi

# ── Detect OS & install system deps ────────────────────────
info "Detecting operating system …"
if command -v apt-get &>/dev/null; then
    info "Debian/Ubuntu detected — installing python3 & pip …"
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip >/dev/null 2>&1
elif command -v dnf &>/dev/null; then
    info "RHEL/Fedora detected — installing python3 & pip …"
    dnf install -y -q python3 python3-pip >/dev/null 2>&1
elif command -v yum &>/dev/null; then
    info "CentOS detected — installing python3 & pip …"
    yum install -y -q python3 python3-pip >/dev/null 2>&1
elif command -v brew &>/dev/null; then
    info "macOS detected — installing python3 via brew …"
    brew install python3 2>/dev/null || true
else
    warn "Unknown OS — make sure python3 and pip3 are installed."
fi

# ── Install Python dependencies ────────────────────────────
info "Installing Python dependencies …"
pip3 install --quiet requests python-dotenv urllib3 --break-system-packages 2>/dev/null \
  || pip3 install --quiet requests python-dotenv urllib3 2>/dev/null \
  || warn "pip install had issues — you may need to install deps manually."

# ── Copy project files ─────────────────────────────────────
info "Installing to ${INSTALL_DIR} …"
mkdir -p "${INSTALL_DIR}"
cp -r . "${INSTALL_DIR}/"

# Create profiles directory
mkdir -p "${INSTALL_DIR}/cli/were/profiles"

# ── Create global command ──────────────────────────────────
info "Creating global command 'acuscanner' …"
cat <<'EOF' > /usr/local/bin/acuscanner
#!/bin/bash
python3 /opt/acunetix-cli/scanner.py "$@"
EOF

chmod +x /usr/local/bin/acuscanner
chmod +x "${INSTALL_DIR}/scanner.py"

# ── Verify installation ───────────────────────────────────
echo ""
success "═══════════════════════════════════════════════"
success "  AcuScan CLI v3.0 installed successfully!"
success "═══════════════════════════════════════════════"
echo ""
info "Next steps:"
echo "  1. Configure:   acuscanner --setup"
echo "  2. Test:         acuscanner --test-connection"
echo "  3. First scan:   acuscanner --scan -u https://example.com"
echo ""
info "Multi-user setup:"
echo "  acuscanner --add-profile alice"
echo "  acuscanner --use-profile alice --test-connection"
echo ""
info "Full help:        acuscanner --help"
echo ""
success "Follow MrpasswordTz on GitHub!"
