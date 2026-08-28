#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Uninstallation Script
# Removes the optional systemd service when present.
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="odysafe-cti"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_ENV_FILE="/etc/${SERVICE_NAME}.env"

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

remove_persistent_service() {
    if [ ! -e "$SERVICE_FILE" ] && [ ! -e "$SERVICE_ENV_FILE" ]; then
        return 0
    fi

    echo -e "${BLUE}[INFO]${NC} Stopping and removing persistent systemd service..."
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if ! run_as_root systemctl disable --now "$SERVICE_NAME"; then
            echo -e "${RED}[ERROR]${NC} Unable to stop $SERVICE_NAME. Uninstallation aborted." >&2
            exit 1
        fi
    else
        echo -e "${YELLOW}[WARNING]${NC} systemd is not running; removing inactive service files only."
    fi

    run_as_root rm -f "$SERVICE_FILE"
    run_as_root rm -f "$SERVICE_ENV_FILE"
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        run_as_root systemctl daemon-reload
        run_as_root systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
    fi
    echo -e "${GREEN}[SUCCESS]${NC} Persistent service and service environment removed"
}

echo -e "${BLUE}[INFO]${NC} Odysafe CTI Platform Uninstaller"
echo ""
echo -e "${YELLOW}This will remove the application and all data.${NC}"
echo "Location: $SCRIPT_DIR"
echo ""

read -p "Continue with uninstallation? [y/N]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[INFO]${NC} Uninstallation cancelled."
    exit 0
fi

remove_persistent_service

echo -e "${BLUE}[INFO]${NC} Removing virtual environment..."
rm -rf "$SCRIPT_DIR/venv" 2>/dev/null || true
echo -e "${GREEN}[SUCCESS]${NC} Virtual environment removed"

echo -e "${BLUE}[INFO]${NC} Removing ODYSAFE runtime cache..."
find "$SCRIPT_DIR/cti-platform" \
    -path "$SCRIPT_DIR/cti-platform/modules/cache" -prune -o \
    -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" \) \
    -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR/cti-platform" \
    -path "$SCRIPT_DIR/cti-platform/modules/cache" -prune -o \
    -type f \( -name "*.pyc" -o -name "*.pyo" \) \
    -delete 2>/dev/null || true
echo -e "${GREEN}[SUCCESS]${NC} ODYSAFE runtime cache removed"

echo ""
read -p "Remove database (all IOCs, sources, settings, incidents)? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR/cti-platform/database" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} Database removed"
else
    echo -e "${BLUE}[INFO]${NC} Database kept"
fi

echo ""
read -p "Remove uploaded files? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR/cti-platform/uploads" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} Uploaded files removed"
else
    echo -e "${BLUE}[INFO]${NC} Uploaded files kept"
fi

echo ""
read -p "Remove exported outputs (IOC exports, STIX conversions, reports)? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR/cti-platform/outputs" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} Output files removed"
else
    echo -e "${BLUE}[INFO]${NC} Output files kept"
fi

echo ""
read -p "Remove modules cache files? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR/cti-platform/modules/cache"/* 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} Modules cache files removed"
else
    echo -e "${BLUE}[INFO]${NC} Modules cache files kept"
fi

echo ""
read -p "Remove cloned CTI repositories (DeepDarkCTI, Ransomware Matrix, Data-Shield)? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR/cti-platform/modules/deepdarkCTI-main" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/cti-platform/modules/ThreatIntel-Reports-main" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/cti-platform/modules/data_shield" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} Cloned repositories removed"
else
    echo -e "${BLUE}[INFO]${NC} Cloned repositories kept"
fi

echo ""
read -p "Remove cached MITRE ATT&CK data (enterprise-attack.json)? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f "$SCRIPT_DIR/docs/enterprise-attack.json" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/docs/enterprise-attack.json.backup" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/docs/enterprise-attack.json.gz" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/docs/enterprise-attack-v19.0.xlsx" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} MITRE ATT&CK data files removed"
else
    echo -e "${BLUE}[INFO]${NC} MITRE ATT&CK data files kept"
fi

echo ""
read -p "Remove SSL certificates? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR/cti-platform/ssl" 2>/dev/null || true
    echo -e "${GREEN}[SUCCESS]${NC} SSL certificates removed"
else
    echo -e "${BLUE}[INFO]${NC} SSL certificates kept"
fi

echo ""
echo -e "${GREEN}${BOLD}========================================${NC}"
echo -e "${GREEN}${BOLD}  Uninstallation Complete${NC}"
echo -e "${GREEN}${BOLD}========================================${NC}"
echo ""
echo -e "${YELLOW}To completely remove ODYSAFE-CTI, delete this directory:${NC}"
echo "  rm -rf $SCRIPT_DIR"
echo ""
