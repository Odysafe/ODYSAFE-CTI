#!/bin/bash

# ============================================================================
# ODYSAFE CTI Platform · Start Script
# ============================================================================

# Colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${CTI_INSTALL_DIR:-$SCRIPT_DIR}"
CTI_PORT="${CTI_PORT:-5001}"

# Helper functions
hline() {
    local width=${1:-60}
    local char="${2:--}"
    local color="${3:-$DIM}"
    printf "${color}"
    printf '%*s' "$width" '' | tr ' ' "$char"
    printf "${NC}\n"
}

box_top() {
    printf "${DIM}+"
    printf '%*s' 62 '' | tr ' ' '-'
    printf "+${NC}\n"
}

box_bottom() {
    printf "${DIM}+"
    printf '%*s' 62 '' | tr ' ' '-'
    printf "+${NC}\n"
}

box_line() {
    local label="$1"
    local value="$2"
    # Box inner width is 62 chars: | + 60 chars content + |
    # Format: 2 spaces + 20 chars label + 2 spaces + 36 chars value = 60
    local max_value_len=36
    local value_display="$value"
    if [ ${#value} -gt $max_value_len ]; then
        value_display="${value:0:33}..."
    fi
    printf "${DIM}|${NC}  ${DIM}%-20s${NC}  ${WHITE}%-${max_value_len}s${NC}${DIM}|${NC}\n" "$label" "$value_display"
}

log_ok()   { printf "  ${GREEN}✔${NC}  %s\n" "$1"; }
log_info() { printf "  ${BLUE}●${NC}  %s\n" "$1"; }
log_warn() { printf "  ${YELLOW}⚠${NC}  %s\n" "$1"; }
log_err()  { printf "  ${RED}✖${NC}  %s\n" "$1" >&2; }
log_dim()  { printf "     ${DIM}%s${NC}\n" "$1"; }

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
    echo ""
    hline 64 "-" "$DIM"
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────

preflight() {
    local ok=1
    local required_files=(
        "cti-platform/templates/memory/index.html"
        "cti-platform/templates/flash_report/index.html"
    )
    local relative_path

    if [ ! -d "$INSTALL_DIR/venv" ]; then
        log_err "Virtual environment not found."
        log_dim "Run ./install.sh first."
        ok=0
    fi

    if [ ! -f "$INSTALL_DIR/cti-platform/app.py" ]; then
        log_err "cti-platform/app.py not found."
        log_dim "Make sure you are running this from the repository root."
        ok=0
    fi

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
            log_dim "Run ./install.sh from a complete Git checkout."
            ok=0
        fi
    done

    local cert="$INSTALL_DIR/cti-platform/ssl/cert.pem"
    local key="$INSTALL_DIR/cti-platform/ssl/key.pem"
    if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
        log_warn "SSL certificates missing · HTTPS may not work."
        log_dim "Run: ./scripts/generate-ssl-cert.sh"
    else
        log_ok "SSL certificate found"
        log_dim "$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/notAfter=/Expires: /')"
    fi

    [ "$ok" -eq 0 ] && exit 1
}

# ── Detect local IP ───────────────────────────────────────────────────────────

get_local_ip() {
    # Try several strategies, fall back to localhost
    local ip
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$ip" ] && ip="127.0.0.1"
    echo "$ip"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    show_banner

    # Info box
    echo ""
    box_top
    box_line "Directory" "$INSTALL_DIR"
    box_line "Port" "$CTI_PORT"
    box_line "Python" "$(python3 --version 2>&1 | awk '{print $2}') (venv)"
    box_bottom

    echo ""
    printf "${BOLD}${CYAN}  > Pre-flight checks${NC}\n"
    preflight

    # Activate virtual environment
    source "$INSTALL_DIR/venv/bin/activate"

    local local_ip
    local_ip=$(get_local_ip)

    echo ""
    hline 64 "=" "$GREEN"
    printf "${GREEN}${BOLD}  [OK] Starting ODYSAFE CTI Platform${NC}\n"
    hline 64 "=" "$GREEN"

    echo ""
    printf "  ${BOLD}${WHITE}Access URLs:${NC}\n"
    echo ""
    printf "    Local:     ${CYAN}${BOLD}https://localhost:${CTI_PORT}${NC}\n"
    printf "    Network:   ${CYAN}${BOLD}https://${local_ip}:${CTI_PORT}${NC}\n"
    echo ""
    printf "  ${DIM}Note: Accept the browser warning for the self-signed certificate${NC}\n"
    echo ""
    hline 64 "-" "$DIM"
    printf "  ${DIM}[Ctrl+C to stop]${NC}\n"
    hline 64 "-" "$DIM"
    echo ""

    # Launch the app
    cd "$INSTALL_DIR/cti-platform"
    exec python app.py
}

main
