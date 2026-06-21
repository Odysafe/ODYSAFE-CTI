#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Uninstallation Script
# User-mode only (no root required)
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

echo -e "${BLUE}[INFO]${NC} Removing virtual environment..."
rm -rf "$SCRIPT_DIR/venv" 2>/dev/null || true
echo -e "${GREEN}[SUCCESS]${NC} Virtual environment removed"

echo -e "${BLUE}[INFO]${NC} Removing Python cache..."
find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}[SUCCESS]${NC} Python cache removed"

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
