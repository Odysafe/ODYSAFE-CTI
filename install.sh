#!/bin/bash

# ============================================================================
# ODYSAFE CTI Platform · Installation Script
# User-space installation (no root required)
# ============================================================================

set -e
set -o pipefail

# ── Colours & styles ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[0;97m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# ASCII drawing characters render correctly even in minimal server locales.
H='-'; V='|'; TL='+'; TR='+'; BL='+'; BR='+'
SH='='; SV='|'; STL='+'; STR='+'; SBL='+'; SBR='+'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${CTI_INSTALL_DIR:-$SCRIPT_DIR}"
CTI_PORT="${CTI_PORT:-5001}"
PINNED_SOURCES="$SCRIPT_DIR/scripts/pinned_sources.json"

STEP_NUM=0
USE_SSL=true
STEP_TOTAL=6

# ── Helpers ───────────────────────────────────────────────────────────────────

_pad() { printf "%-${1}s" "$2"; }

hline() {
    # hline <width> <char> <color>
    local w=${1:-60} c=${2:-$H} col=${3:-$DIM}
    printf "${col}"
    printf "%${w}s" | tr ' ' "$c"
    printf "${NC}\n"
}

box_top()    { printf "${CYAN}${TL}"; printf "%${1}s" | tr ' ' "$H"; printf "${TR}${NC}\n"; }
box_bottom() { printf "${CYAN}${BL}"; printf "%${1}s" | tr ' ' "$H"; printf "${BR}${NC}\n"; }
box_line()   { printf "${CYAN}${V}${NC} %-$(( $1 - 2 ))s ${CYAN}${V}${NC}\n" "$2"; }

log_ok()   { printf "  ${GREEN}✔${NC}  %s\n" "$1"; }
log_info() { printf "  ${BLUE}●${NC}  %s\n" "$1"; }
log_warn() { printf "  ${YELLOW}⚠${NC}  %s\n" "$1"; }
log_err()  { printf "  ${RED}✖${NC}  %s\n" "$1" >&2; }
log_dim()  { printf "     ${DIM}%s${NC}\n" "$1"; }

# Yes/No prompt · empty Enter uses default (Y or N)
prompt_yes_no() {
    local question="$1"
    local default="${2:-N}"
    local hint reply

    if [[ "$default" == "Y" || "$default" == "y" ]]; then
        hint="[Y/n]"
    else
        hint="[y/N]"
    fi

    read -r -p "  ${question} ${hint}: " reply
    reply="${reply:-$default}"

    [[ "$reply" =~ ^[Yy]$ ]]
}

# Terminal progress bar (0-100) · single line, cleared on each update
show_progress_bar() {
    local pct="${1:-0}"
    local msg="${2:-Working...}"
    local width=40
    local filled empty bar i

    pct=$(( pct < 0 ? 0 : (pct > 100 ? 100 : pct) ))
    filled=$(( pct * width / 100 ))
    empty=$(( width - filled ))
    bar=""
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=0; i<empty; i++)); do bar+="-"; done

    # Truncate message so the line never wraps or leaves ghost characters
    msg="${msg:0:52}"
    printf "\r\033[K  ${CYAN}[${bar}]${NC} ${WHITE}%3d%%${NC} ${DIM}%s${NC}" "$pct" "$msg"
}

finish_progress_bar() {
    local pct="${1:-100}"
    local msg="${2:-Complete}"
    show_progress_bar "$pct" "$msg"
    printf "\n"
}

clear_progress_line() {
    printf "\r\033[K"
}

# Read a dotted key from scripts/pinned_sources.json (e.g. mitre_attack.commit)
pinned_value() {
    local key="$1"
    python3 - "$PINNED_SOURCES" "$key" << 'PYEOF'
import json
import sys

path, dotted = sys.argv[1], sys.argv[2]
data = json.load(open(path, encoding="utf-8"))
value = data
for part in dotted.split("."):
    value = value[part]
print(value)
PYEOF
}

mitre_download_url() {
    local commit path
    commit="$(pinned_value mitre_attack.commit)"
    path="$(pinned_value mitre_attack.path)"
    printf 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/%s/%s' "$commit" "$path"
}

ensure_required_application_files() {
    local required_files=(
        "cti-platform/templates/memory/index.html"
        "cti-platform/templates/flash_report/index.html"
    )
    local relative_path
    local repair_failed=0

    for relative_path in "${required_files[@]}"; do
        if [ -f "$INSTALL_DIR/$relative_path" ]; then
            continue
        fi

        log_warn "Required application file is missing: $relative_path"
        if git -C "$INSTALL_DIR" ls-files --error-unmatch "$relative_path" >/dev/null 2>&1; then
            log_info "Restoring $relative_path from the current Git checkout..."
            git -C "$INSTALL_DIR" restore --worktree -- "$relative_path"
        fi

        if [ -f "$INSTALL_DIR/$relative_path" ]; then
            log_ok "Restored $relative_path"
        else
            log_err "Unable to restore $relative_path"
            repair_failed=1
        fi
    done

    if [ "$repair_failed" -ne 0 ]; then
        log_err "The source checkout is incomplete. Installation cannot continue safely."
        log_dim "Update or recreate the Git checkout, then run ./install.sh again."
        exit 1
    fi
}

# Remove executable/template caches left by a previous ODYSAFE version.
# Deliberately keep modules/cache: it contains CTI downloads and user choices,
# not Python bytecode or rendered Flask templates.
clear_odysafe_runtime_cache() {
    log_info "Clearing previous ODYSAFE runtime cache..."

    find "$INSTALL_DIR/cti-platform" \
        -path "$INSTALL_DIR/cti-platform/modules/cache" -prune -o \
        -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" \) \
        -exec rm -rf {} + 2>/dev/null || true
    find "$INSTALL_DIR/cti-platform" \
        -path "$INSTALL_DIR/cti-platform/modules/cache" -prune -o \
        -type f \( -name "*.pyc" -o -name "*.pyo" \) \
        -delete 2>/dev/null || true

    log_ok "ODYSAFE runtime cache cleared"
}

# Download MITRE JSON using Python (same method as the web UI · no curl required)
download_mitre_json() {
    local dest_file="$1"
    local py_ok=0

    if ! command -v python3 &>/dev/null; then
        log_err "python3 is required to download MITRE ATT&CK data"
        return 1
    fi

    show_progress_bar 0 "Connecting to MITRE GitHub..."
    if python3 - "$dest_file" "$PINNED_SOURCES" << 'PYEOF'
import json
import sys
import urllib.request

dest = sys.argv[1]
pinned_path = sys.argv[2]
with open(pinned_path, encoding="utf-8") as handle:
    pinned = json.load(handle)
commit = pinned["mitre_attack"]["commit"]
path = pinned["mitre_attack"]["path"]
URL = (
    f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{commit}/{path}"
)
BAR_WIDTH = 40

def draw_bar(pct, msg):
    pct = max(0, min(100, int(pct)))
    filled = min(BAR_WIDTH, int(BAR_WIDTH * pct / 100))
    bar = "#" * filled + "-" * (BAR_WIDTH - filled)
    msg = msg[:52]
    sys.stdout.write(f"\r\033[K  [{bar}] {pct:3d}% {msg}")
    sys.stdout.flush()

def reporthook(block_num, block_size, total_size):
    if total_size and total_size > 0:
        downloaded = block_num * block_size
        pct = min(100, int(downloaded * 100 / total_size))
        mb = downloaded / (1024 * 1024)
        total_mb = total_size / (1024 * 1024)
        draw_bar(pct, f"Downloading MITRE ATT&CK ({mb:.1f}/{total_mb:.1f} MB)")
    else:
        draw_bar(min(99, (block_num * 7) % 100), "Downloading MITRE ATT&CK...")

try:
    draw_bar(0, "Connecting...")
    urllib.request.urlretrieve(URL, dest, reporthook)
    draw_bar(100, "Complete")
    sys.stdout.write("\n")
    sys.stdout.flush()
except Exception as exc:
    sys.stdout.write("\n")
    print(f"ERROR:{exc}", file=sys.stderr)
    sys.exit(1)
PYEOF
    then
        py_ok=1
    fi

    if [ "$py_ok" -eq 1 ]; then
        return 0
    fi
    clear_progress_line
    return 1
}

# Git clone at a pinned commit (shallow fetch)
clone_repo_at_commit() {
    local url="$1"
    local target="$2"
    local label="$3"
    local commit="$4"
    local clone_status=0

    mkdir -p "$(dirname "$target")"
    rm -rf "$target"
    show_progress_bar 0 "Preparing: ${label}..."

    set +e
    show_progress_bar 10 "${label}: Initializing repository..."
    git init "$target" >/dev/null 2>&1
    git -C "$target" remote add origin "$url" >/dev/null 2>&1
    show_progress_bar 35 "${label}: Fetching pinned snapshot..."
    git -C "$target" fetch --depth 1 origin "$commit" >/dev/null 2>&1
    clone_status=$?
    if [ "$clone_status" -eq 0 ]; then
        show_progress_bar 80 "${label}: Checking out snapshot..."
        git -C "$target" checkout FETCH_HEAD >/dev/null 2>&1
        clone_status=$?
    fi
    set -e

    if [ "$clone_status" -eq 0 ]; then
        finish_progress_bar 100 "${label}: Complete (pinned ${commit:0:12})"
        return 0
    fi

    clear_progress_line
    printf "\n"
    return 1
}

# Git clone with phase-aware progress (parses git --progress output correctly)
clone_repo_with_progress() {
    local url="$1"
    local target="$2"
    local label="$3"
    local clone_status=0
    local line subpct overall=0

    mkdir -p "$(dirname "$target")"
    show_progress_bar 0 "Preparing: ${label}..."

    set +e
    while IFS= read -r line; do
        line="${line//$'\r'/}"
        [[ -z "$line" ]] && continue

        if [[ "$line" =~ [Ee]numerating\ objects ]]; then
            overall=5
            show_progress_bar "$overall" "${label}: Enumerating objects..."
        elif [[ "$line" =~ [Cc]ounting\ objects:\ ([0-9]+)% ]]; then
            subpct="${BASH_REMATCH[1]}"
            overall=$(( 5 + subpct * 10 / 100 ))
            show_progress_bar "$overall" "${label}: Counting objects (${subpct}%)"
        elif [[ "$line" =~ [Cc]ompressing\ objects:\ ([0-9]+)% ]]; then
            subpct="${BASH_REMATCH[1]}"
            overall=$(( 15 + subpct * 15 / 100 ))
            show_progress_bar "$overall" "${label}: Compressing objects (${subpct}%)"
        elif [[ "$line" =~ [Rr]eceiving\ objects:\ ([0-9]+)% ]]; then
            subpct="${BASH_REMATCH[1]}"
            overall=$(( 30 + subpct * 45 / 100 ))
            show_progress_bar "$overall" "${label}: Receiving objects (${subpct}%)"
        elif [[ "$line" =~ [Rr]esolving\ deltas:\ ([0-9]+)% ]]; then
            subpct="${BASH_REMATCH[1]}"
            overall=$(( 75 + subpct * 15 / 100 ))
            show_progress_bar "$overall" "${label}: Resolving deltas (${subpct}%)"
        elif [[ "$line" =~ [Uu]pdating\ files:\ ([0-9]+)% ]]; then
            subpct="${BASH_REMATCH[1]}"
            overall=$(( 90 + subpct * 9 / 100 ))
            show_progress_bar "$overall" "${label}: Checking out files (${subpct}%)"
        elif [[ "$line" =~ [Cc]hecking\ out\ files:\ ([0-9]+)% ]]; then
            subpct="${BASH_REMATCH[1]}"
            overall=$(( 90 + subpct * 9 / 100 ))
            show_progress_bar "$overall" "${label}: Checking out files (${subpct}%)"
        elif [[ "$line" =~ [Ff]iltering\ content ]]; then
            show_progress_bar 92 "${label}: Filtering content..."
        fi
    done < <(git clone --depth 1 --progress "$url" "$target" 2>&1)
    clone_status=$?
    set -e

    if [ "$clone_status" -eq 0 ]; then
        finish_progress_bar 100 "${label}: Complete"
        return 0
    fi

    clear_progress_line
    printf "\n"
    return 1
}

step() {
    (( STEP_NUM++ )) || true
    echo ""
    printf "${BOLD}${CYAN}  ┌─ Step ${STEP_NUM}/${STEP_TOTAL}  ${WHITE}%s${NC}\n" "$1"
    printf "${CYAN}  └${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${H}${NC}\n"
}

# ── Banner ────────────────────────────────────────────────────────────────────

show_banner() {
    clear
    echo ""
    echo -e "${MAGENTA}${BOLD}"
    cat << 'EOF'
   ██████╗ ██████╗ ██╗   ██╗███████╗ █████╗ ███████╗███████╗
  ██╔═══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝
  ██║   ██║██║  ██║ ╚████╔╝ ███████╗███████║█████╗  █████╗
  ██║   ██║██║  ██║  ╚██╔╝  ╚════██║██╔══██║██╔══╝  ██╔══╝
  ╚██████╔╝██████╔╝   ██║   ███████║██║  ██║██║     ███████╗
   ╚═════╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝
EOF
    echo -e "${NC}"
    printf "             ${CYAN}${BOLD}Cyber Threat Intelligence Platform${NC}\n"
    printf "             ${DIM}https://github.com/odysafe/cti-platform${NC}\n"
    echo ""
    hline 64 "$H" "$DIM"
    printf "  ${DIM}%-28s${NC}  ${WHITE}%-28s${NC}\n" "Install directory" "$INSTALL_DIR"
    printf "  ${DIM}%-28s${NC}  ${WHITE}%-28s${NC}\n" "HTTPS port" "$CTI_PORT"
    printf "  ${DIM}%-28s${NC}  ${WHITE}%-28s${NC}\n" "Host" "$(hostname -f 2>/dev/null || hostname)"
    hline 64 "$H" "$DIM"
    echo ""
}

# ── Step 1 – Prerequisites ────────────────────────────────────────────────────

check_prerequisites() {
    step "Checking prerequisites"

    local missing=()

    if command -v python3 &>/dev/null; then
        local py_version=$(python3 --version 2>&1 | awk '{print $2}')
        local py_major=$(echo "$py_version" | cut -d. -f1)
        local py_minor=$(echo "$py_version" | cut -d. -f2)

        if [ "$py_major" -ge 3 ] && [ "$py_minor" -ge 10 ]; then
            log_ok "Python $py_version (>= 3.10 OK)"
        elif [ "$py_major" -ge 3 ] && [ "$py_minor" -ge 8 ]; then
            log_warn "Python $py_version · 3.10+ recommended (3.8+ may work but is not CI-tested)"
        else
            log_err "Python $py_version · version 3.8 or higher required"
            missing+=("python3.8+")
        fi
    else
        log_err "python3 not found"; missing+=("python3")
    fi

    if python3 -m pip --version &>/dev/null; then
        log_ok "pip     · $(python3 -m pip --version 2>&1 | awk '{print $1,$2}')"
    else
        log_err "pip not found"; missing+=("python3-pip")
    fi

    if command -v git &>/dev/null; then
        log_ok "git     · $(git --version)"
    else
        log_err "git not found"; missing+=("git")
    fi

    if command -v openssl &>/dev/null; then
        log_ok "openssl · $(openssl version)"
    else
        log_err "openssl not found"; missing+=("openssl")
    fi

    # Check for system library required by python-magic
    if ldconfig -p | grep -q libmagic; then
        log_ok "libmagic · system library found"
    else
        log_warn "libmagic not found · python-magic may fail"
        log_dim "Fix: sudo apt install -y libmagic1"
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo ""
        log_err "Missing: ${missing[*]}"
        log_info "Fix: sudo apt install ${missing[*]}"
        exit 1
    fi

    log_ok "All prerequisites satisfied"
}

# ── Step 2 – Python venv ──────────────────────────────────────────────────────

setup_python_environment() {
    step "Setting up Python virtual environment"

    cd "$INSTALL_DIR"

    local new_venv=0
    if [ ! -d "venv" ]; then
        log_info "Creating virtual environment…"
        python3 -m venv venv
        new_venv=1
        log_ok "Virtual environment created"
    else
        log_ok "Virtual environment already exists"
    fi

    source venv/bin/activate

    if [ "$new_venv" -eq 1 ] || [ "${CTI_UPGRADE_PIP:-0}" = "1" ]; then
        log_info "Upgrading pip / setuptools / wheel…"
        if pip install --upgrade pip setuptools wheel 2>&1 | tail -n 5; then
            log_ok "pip upgraded"
        else
            log_warn "pip upgrade failed · continuing with bundled version"
            log_dim "Force upgrade later: CTI_UPGRADE_PIP=1 ./install.sh"
        fi
    else
        log_ok "Skipping pip upgrade (set CTI_UPGRADE_PIP=1 to force)"
    fi

    local req_file="scripts/requirements.txt"
    if [ -f "scripts/requirements.lock" ]; then
        req_file="scripts/requirements.lock"
        log_info "Using locked dependencies (scripts/requirements.lock)"
    fi

    if [ ! -f "$req_file" ]; then
        log_err "$req_file not found"
        exit 1
    fi

    local pkg_count
    pkg_count=$(grep -cE '^[^#[:space:]]' "$req_file" 2>/dev/null || echo "?")
    log_info "Installing $pkg_count packages from ${req_file##*/} (may take a few minutes)…"

    # Create temporary log file for pip output
    local pip_log=$(mktemp)

    # Run pip install with progress output but capture errors
    if pip install --prefer-binary -r "$req_file" 2>&1 | tee "$pip_log"; then
        log_ok "Core Python dependencies installed"
        rm -f "$pip_log"
    else
        local exit_code=$?
        echo ""
        log_err "Failed to install Python dependencies (exit code: $exit_code)"
        echo ""

        # Show last 50 lines of error output
        if [ -f "$pip_log" ]; then
            echo -e "${RED}Error details:${NC}"
            echo "---"
            tail -n 50 "$pip_log"
            echo "---"
            rm -f "$pip_log"
        fi

        echo ""
        echo -e "${YELLOW}${BOLD}Troubleshooting steps:${NC}"
        echo ""
        echo -e "  ${CYAN}1.${NC} Check your internet connection:"
        echo -e "     ${DIM}ping -c 3 pypi.org${NC}"
        echo ""
        echo -e "  ${CYAN}2.${NC} Try upgrading pip manually:"
        echo -e "     ${DIM}source venv/bin/activate && pip install --upgrade pip${NC}"
        echo ""
        echo -e "  ${CYAN}3.${NC} Install packages one by one to identify the problematic package:"
        echo -e "     ${DIM}source venv/bin/activate${NC}"
        echo -e "     ${DIM}pip install <package_name>${NC}"
        echo ""
        echo -e "  ${CYAN}4.${NC} If you see 'No matching distribution found', check Python version:"
        echo -e "     ${DIM}python3 --version${NC} (must be 3.8 or higher)"
        echo ""
        echo -e "  ${CYAN}5.${NC} For system library errors (e.g., python-magic), install system dependencies:"
        echo -e "     ${DIM}sudo apt update && sudo apt install -y libmagic1${NC}"
        echo ""
        echo -e "  ${CYAN}6.${NC} Clear pip cache and retry:"
        echo -e "     ${DIM}pip cache purge && ./install.sh${NC}"
        echo ""
        echo -e "  ${CYAN}7.${NC} Check the full error log above for specific package failures"
        echo ""
        log_info "After fixing the issue, run ./install.sh again"
        exit 1
    fi
}

# ── Step 3 – Directories ──────────────────────────────────────────────────────

create_directories() {
    step "Creating required directories"

    local dirs=(
        "uploads"
        "outputs/iocs"
        "outputs/stix"
        "outputs/reports"
        "database"
        "modules/cache"
        "ssl"
    )

    cd "$INSTALL_DIR/cti-platform"
    for d in "${dirs[@]}"; do
        mkdir -p "$d"
        log_ok "cti-platform/$d"
    done
}

# ── Step 4 – Protocol selection ───────────────────────────────────────────────

select_protocol() {
    step "Select protocol"

    echo ""
    printf "  ${CYAN}?${NC}  ${BOLD}Choose connection protocol:${NC}\n\n"
    printf "     ${GREEN}[1]${NC} HTTPS (secure, self-signed certificate)\n"
    printf "     ${YELLOW}[2]${NC} HTTP (insecure, development only)\n"
    echo ""
    printf "  ${DIM}Recommendation: HTTPS for security${NC}\n"
    echo ""
    printf "  Enter choice [1/2, default: 1]: "
    read -r protocol_choice
    echo ""

    if [[ "$protocol_choice" == "2" ]]; then
        USE_SSL=false
        log_warn "HTTP selected · traffic will be unencrypted"
        log_dim "Not recommended for production environments"
        echo ""
        printf "  ${CYAN}?${NC} ${BOLD}Enable HTTPS later?${NC}\n\n"
        printf "     To switch to HTTPS after installation:\n\n"
        printf "     ${DIM}1. Generate certificate:${NC}\n"
        printf "        ${GREEN}./scripts/generate-ssl-cert.sh${NC}\n\n"
        printf "     ${DIM}2. Enable SSL in config:${NC}\n"
        printf "        ${GREEN}export CTI_USE_SSL=true${NC}\n"
        printf "        ${GREEN}./start.sh${NC}\n\n"
        printf "     ${DIM}Or edit .env file:${NC}\n"
        printf "        ${GREEN}echo 'CTI_USE_SSL=true' >> .env${NC}\n\n"
        hline 64 "-" "$DIM"
    else
        USE_SSL=true
        log_ok "HTTPS selected · secure connection"
    fi
}

# ── Step 5 – SSL Certificate ──────────────────────────────────────────────────

generate_ssl_certificate() {
    if [ "$USE_SSL" != "true" ]; then
        log_info "Skipping SSL certificate generation (HTTP mode)"
        return 0
    fi

    step "Generating SSL certificate"

    local ssl_dir="$INSTALL_DIR/cti-platform/ssl"
    local cert_file="$ssl_dir/cert.pem"
    local key_file="$ssl_dir/key.pem"

    if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
        log_ok "SSL certificate already present · skipping"
        log_dim "$(openssl x509 -in "$cert_file" -noout -subject -dates 2>/dev/null | tr '\n' '  ')"
        return 0
    fi

    mkdir -p "$ssl_dir"
    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname || echo "localhost")

    log_info "Generating RSA-4096 self-signed certificate for: ${BOLD}$hostname${NC}"

    openssl req -x509 -newkey rsa:4096 -keyout "$key_file" -out "$cert_file" \
        -days 365 -nodes \
        -subj "/C=FR/ST=France/L=Paris/O=Odysafe/OU=CTI Platform/CN=$hostname" \
        -addext "subjectAltName=DNS:$hostname,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chmod 600 "$key_file"
    chmod 644 "$cert_file"

    log_ok "Certificate generated  → cti-platform/ssl/cert.pem"
    log_ok "Private key secured    → cti-platform/ssl/key.pem  (chmod 600)"
}

# ── Step 6 – Third-party CTI data ─────────────────────────────────────────────

install_mitre_data() {
    local mitre_file="$INSTALL_DIR/docs/enterprise-attack.json"

    if [ -f "$mitre_file" ]; then
        local sz
        sz=$(du -h "$mitre_file" | cut -f1)
        log_ok "enterprise-attack.json found (${sz})"
        return 0
    fi

    log_warn "MITRE ATT&CK STIX bundle not found"
    log_dim "Expected: docs/enterprise-attack.json"
    log_dim "File size: ~50 MB (large download)"
    log_dim "Required for the MITRE ATT&CK module in Analysis"
    mkdir -p "$INSTALL_DIR/docs"
    if download_mitre_json "$mitre_file"; then
        local sz
        sz=$(du -h "$mitre_file" | cut -f1)
        log_ok "MITRE ATT&CK downloaded (${sz})"
    else
        log_warn "MITRE ATT&CK download failed"
        log_dim "Download later from Analysis → MITRE ATT&CK"
        log_dim "Manual: place enterprise-attack.json in docs/"
    fi
}

install_optional_repo() {
    local name="$1"
    local repo_key="$2"
    local target="$3"
    local size_note="$4"
    local url commit

    url="$(pinned_value "${repo_key}.url")"
    commit="$(pinned_value "${repo_key}.commit")"

    if [ -d "$target/.git" ]; then
        log_ok "${name} repository already present"
        return 0
    fi

    if clone_repo_at_commit "$url" "$target" "$name" "$commit"; then
        log_ok "${name} downloaded (pinned snapshot)"
    else
        log_warn "Clone failed for ${name}"
        log_dim "Manual: git clone ${url} ${target} && git -C ${target} checkout ${commit}"
    fi
}

install_third_party_data() {
    step "Third-party CTI data"

    local mitre_file="$INSTALL_DIR/docs/enterprise-attack.json"
    local deepdark_target="$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main"
    local ransomware_target="$INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main"
    local missing=0

    [ -f "$mitre_file" ] || missing=1
    [ -d "$deepdark_target/.git" ] || missing=1
    [ -d "$ransomware_target/.git" ] || missing=1

    if [ "$missing" -eq 0 ]; then
        log_ok "MITRE ATT&CK, DeepDarkCTI, and Ransomware Tool Matrix are already installed"
        return 0
    fi

    echo ""
    printf "  ${CYAN}?${NC}  ${BOLD}Install all missing third-party CTI data?${NC}\n\n"
    [ -f "$mitre_file" ] || printf "     - MITRE ATT&CK STIX bundle (~50 MB)\n"
    [ -d "$deepdark_target/.git" ] || printf "     - DeepDarkCTI pinned repository\n"
    [ -d "$ransomware_target/.git" ] || printf "     - Ransomware Tool Matrix pinned repository\n"
    echo ""

    if ! prompt_yes_no "Install all missing third-party data now?" "Y"; then
        log_info "Third-party CTI data installation skipped"
        return 0
    fi

    install_mitre_data

    install_optional_repo \
        "DeepDarkCTI" \
        "deepdarkcti" \
        "$deepdark_target" \
        ""

    install_optional_repo \
        "Ransomware Tool Matrix" \
        "ransomware_tool_matrix" \
        "$ransomware_target" \
        ""
}

# ── Summary ───────────────────────────────────────────────────────────────────

show_summary() {
    local W=62
    echo ""
    hline $W "$SH" "$GREEN"
    printf "${GREEN}${BOLD}  ✔  Installation complete!${NC}\n"
    hline $W "$SH" "$GREEN"
    echo ""

    printf "${BOLD}${CYAN}  ▸ Quick start${NC}\n\n"
    printf "    ${DIM}# Launch the platform${NC}\n"
    printf "    ${GREEN}./start.sh${NC}\n"
    echo ""
    printf "    ${DIM}# Or manually${NC}\n"
    printf "    ${GREEN}source venv/bin/activate${NC}\n"
    printf "    ${GREEN}cd cti-platform && python app.py${NC}\n"
    echo ""

    printf "${BOLD}${CYAN}  ▸ Permanent service (Debian/Ubuntu)${NC}\n\n"
    printf "    ${GREEN}./scripts/install-systemd-service.sh install${NC}\n"
    printf "    ${DIM}Starts now, restarts on failure, and starts automatically after reboot.${NC}\n"
    echo ""

    printf "${BOLD}${CYAN}  ▸ Access URL${NC}\n\n"
    if [ "$USE_SSL" == "true" ]; then
        printf "    ${WHITE}${BOLD}https://localhost:${CTI_PORT}${NC}\n"
        printf "    ${DIM}Accept the browser certificate warning${NC}\n"
    else
        printf "    ${YELLOW}${BOLD}http://localhost:${CTI_PORT}${NC}\n"
        printf "    ${YELLOW}⚠ Unencrypted · HTTPS recommended for production${NC}\n"
    fi
    echo ""

    printf "${BOLD}${CYAN}  ▸ Data paths${NC}\n\n"
    local base="$INSTALL_DIR/cti-platform"
    printf "    ${DIM}%-22s${NC}  %s\n" "Database"     "$base/database/"
    printf "    ${DIM}%-22s${NC}  %s\n" "Uploads"      "$base/uploads/"
    printf "    ${DIM}%-22s${NC}  %s\n" "IOC exports"  "$base/outputs/iocs/"
    printf "    ${DIM}%-22s${NC}  %s\n" "STIX bundles" "$base/outputs/stix/"
    printf "    ${DIM}%-22s${NC}  %s\n" "Reports"      "$base/outputs/reports/"
    printf "    ${DIM}%-22s${NC}  %s\n" "SSL certs"    "$base/ssl/"
    echo ""

    if [ ! -f "$INSTALL_DIR/docs/enterprise-attack.json" ]; then
        hline $W "$H" "$YELLOW"
        printf "  ${YELLOW}⚠${NC}  MITRE ATT&CK data not installed (~50 MB).\n"
        log_dim "Download from Analysis → MITRE ATT&CK, or:"
        log_dim "python3 -c \"import urllib.request; urllib.request.urlretrieve('$(mitre_download_url)', 'docs/enterprise-attack.json')\""
        hline $W "$H" "$YELLOW"
        echo ""
    fi

    if [ ! -d "$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main/.git" ]; then
        hline $W "$H" "$YELLOW"
        printf "  ${YELLOW}⚠${NC}  DeepDarkCTI not installed.\n"
        log_dim "git clone $(pinned_value deepdarkcti.url) $INSTALL_DIR/cti-platform/modules/deepdarkCTI-main"
        log_dim "git -C $INSTALL_DIR/cti-platform/modules/deepdarkCTI-main checkout $(pinned_value deepdarkcti.commit)"
        hline $W "$H" "$YELLOW"
        echo ""
    fi

    if [ ! -d "$INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main/.git" ]; then
        hline $W "$H" "$YELLOW"
        printf "  ${YELLOW}⚠${NC}  Ransomware Tool Matrix not installed.\n"
        log_dim "git clone $(pinned_value ransomware_tool_matrix.url) $INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main"
        log_dim "git -C $INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main checkout $(pinned_value ransomware_tool_matrix.commit)"
        hline $W "$H" "$YELLOW"
        echo ""
    fi

    hline $W "$H" "$DIM"
    if [ "$USE_SSL" != "true" ]; then
        printf "  ${DIM}Enable HTTPS:  CTI_USE_SSL=true ./start.sh${NC}\n"
        printf "  ${DIM}Or generate cert: ./scripts/generate-ssl-cert.sh${NC}\n"
    else
        printf "  ${DIM}Regenerate SSL: ./scripts/generate-ssl-cert.sh${NC}\n"
    fi
    hline $W "$H" "$DIM"
    echo ""

    # Final prominent call to action
    hline $W "=" "$GREEN"
    printf "${GREEN}${BOLD}  Start the platform:${NC}\n\n"
    printf "    ${GREEN}${BOLD}./start.sh${NC}\n\n"
    printf "    ${DIM}Then open: https://localhost:${CTI_PORT}${NC}\n"
    hline $W "=" "$GREEN"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    show_banner

    if [ ! -d "$INSTALL_DIR/cti-platform" ]; then
        log_err "cti-platform/ directory not found in $INSTALL_DIR"
        log_err "Run this script from the repository root"
        exit 1
    fi

    ensure_required_application_files
    clear_odysafe_runtime_cache
    check_prerequisites
    setup_python_environment
    create_directories
    select_protocol
    generate_ssl_certificate
    install_third_party_data

    show_summary
}

main
