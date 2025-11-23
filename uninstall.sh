#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Uninstallation Script
# Complete uninstallation script for Odysafe CTI Platform
# ============================================================================

set -e  # Stop on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/odysafe-cti-platform"
SERVICE_USER="odysafe-cti-platform"
SERVICE_GROUP="odysafe-cti-platform"
SERVICE_FILE="odysafe-cti-platform.service"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Stop and disable service
stop_service() {
    log_info "Stopping Odysafe CTI Platform service..."
    
    if systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null; then
        systemctl stop "$SERVICE_FILE"
        log_success "Service stopped"
    else
        log_info "Service is not running"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_FILE" 2>/dev/null; then
        systemctl disable "$SERVICE_FILE"
        log_success "Service disabled"
    else
        log_info "Service is not enabled"
    fi
}

# Remove systemd service
remove_service() {
    log_info "Removing systemd service..."
    
    if [ -f "/etc/systemd/system/$SERVICE_FILE" ]; then
        rm -f "/etc/systemd/system/$SERVICE_FILE"
        systemctl daemon-reload
        log_success "Systemd service removed"
    else
        log_info "Service file not found"
    fi
}

# Remove installation files
remove_files() {
    log_info "Removing installation files..."
    
    if [ -d "$INSTALL_DIR" ]; then
        # Remove everything: application, repos, venv, cache, etc.
        log_info "Removing all installation files including:"
        log_info "  - Application files"
        log_info "  - Python virtual environment (venv)"
        log_info "  - Repositories (iocsearcher, txt2stix)"
        log_info "  - All caches and temporary files"
        
        rm -rf "$INSTALL_DIR"
        log_success "Installation files removed"
    else
        log_info "Installation directory not found: $INSTALL_DIR"
    fi
}

# Remove service user
remove_service_user() {
    log_info "Removing service user..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        read -p "Do you want to remove the service user '$SERVICE_USER'? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            userdel "$SERVICE_USER" 2>/dev/null || true
            log_success "Service user removed"
        else
            log_info "Service user kept"
        fi
    else
        log_info "Service user does not exist"
    fi
}

# Remove data (always removes everything including IOCs)
remove_data() {
    log_warning "Removing all application data including:"
    log_warning "  - All IOCs (database)"
    log_warning "  - Uploaded files"
    log_warning "  - Generated outputs"
    log_warning "  - Database files"
    log_warning "  - Cache files"
    
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing all application data..."
        if [ -d "$INSTALL_DIR/cti-platform" ]; then
            rm -rf "$INSTALL_DIR/cti-platform/uploads"/* 2>/dev/null || true
            rm -rf "$INSTALL_DIR/cti-platform/outputs"/* 2>/dev/null || true
            rm -rf "$INSTALL_DIR/cti-platform/database"/* 2>/dev/null || true
            rm -rf "$INSTALL_DIR/cti-platform/modules/cache"/* 2>/dev/null || true
            log_success "All application data (including IOCs) removed"
        fi
    fi
}

# Main uninstallation function
main() {
    echo ""
    log_info "=========================================="
    log_info "Odysafe CTI Platform Uninstallation"
    log_info "=========================================="
    echo ""
    
    check_root
    
    # Confirm uninstallation
    log_warning "This will uninstall Odysafe CTI Platform and remove all files."
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
    
    stop_service
    remove_service
    
    # Remove all data including IOCs (no confirmation needed - uninstall means everything)
    remove_data
    
    # Remove installation files (includes venv, repos, cache, everything)
    remove_files
    
    remove_service_user
    
    echo ""
    log_success "=========================================="
    log_success "Uninstallation completed successfully!"
    log_success "=========================================="
    echo ""
    log_info "Odysafe CTI Platform has been completely removed from the system"
    echo ""
}

# Run main function
main

