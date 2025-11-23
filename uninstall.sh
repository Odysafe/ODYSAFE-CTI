#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Uninstallation Script
# Complete uninstallation script for Odysafe CTI Platform
# ============================================================================

# Note: We use set -e selectively. Some functions need to handle errors themselves.
set -e  # Stop on error by default

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/odysafe-cti-platform"
SERVICE_USER="odysafe-cti-platform"
SERVICE_GROUP="odysafe-cti-platform"
SERVICE_FILE="odysafe-cti-platform.service"
RENEWAL_TIMER_FILE="odysafe-cti-platform-cert-renewal.timer"
RENEWAL_SERVICE_FILE="odysafe-cti-platform-cert-renewal.service"
JOURNALD_CONF_FILE="journald-cti-platform.conf"
JOURNALD_CONF_DIR="/etc/systemd/journald.conf.d"

# Global variables for environment detection
IS_ROOT=false
HAS_SUDO=false
DISTRO=""

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

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

log_step() {
    echo -e "${CYAN}${BOLD}>>>${NC} ${BOLD}$1${NC}"
}

# ============================================================================
# ENVIRONMENT DETECTION
# ============================================================================

detect_environment() {
    log_step "Detecting environment..."
    
    # Detect root/sudo
    if [ "$EUID" -eq 0 ]; then
        IS_ROOT=true
        log_info "Running as root"
    else
        IS_ROOT=false
        if command -v sudo &> /dev/null; then
            HAS_SUDO=true
            log_info "Running as regular user with sudo available"
        else
            HAS_SUDO=false
            log_error "Not running as root and sudo is not available"
            log_error "Please run this script as root or install sudo"
            exit 1
        fi
    fi
    
    # Detect distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        log_info "Distribution detected: $DISTRO"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        log_info "Distribution detected: Debian"
    elif [ -f /etc/redhat-release ]; then
        if grep -qi "centos" /etc/redhat-release; then
            DISTRO="centos"
        elif grep -qi "rocky" /etc/redhat-release; then
            DISTRO="rocky"
        elif grep -qi "almalinux" /etc/redhat-release; then
            DISTRO="almalinux"
        else
            DISTRO="rhel"
        fi
        log_info "Distribution detected: $DISTRO"
    else
        DISTRO="unknown"
        log_warning "Could not detect distribution"
    fi
    
    log_success "Environment detection complete"
}

# ============================================================================
# CHECK INSTALLATION
# ============================================================================

check_installation() {
    log_step "Checking installation..."
    
    local found=false
    
    # Check if service exists
    if [ -f "/etc/systemd/system/$SERVICE_FILE" ]; then
        log_info "Service file found: /etc/systemd/system/$SERVICE_FILE"
        found=true
    fi
    
    # Check if installation directory exists
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Installation directory found: $INSTALL_DIR"
        found=true
    fi
    
    # Check if service user exists
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "Service user found: $SERVICE_USER"
        found=true
    fi
    
    if [ "$found" = false ]; then
        log_warning "No installation found. Nothing to uninstall."
        return 1
    fi
    
    return 0
}

# ============================================================================
# STOP SERVICE
# ============================================================================

stop_service() {
    log_step "Stopping Odysafe CTI Platform service..."
    
    if [ "$IS_ROOT" = true ]; then
        if systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null; then
            if systemctl stop "$SERVICE_FILE" 2>/dev/null; then
                log_success "Service stopped"
            else
                log_warning "Failed to stop service, but continuing..."
            fi
        else
            log_info "Service is not running"
        fi
        
        if systemctl is-enabled --quiet "$SERVICE_FILE" 2>/dev/null; then
            if systemctl disable "$SERVICE_FILE" 2>/dev/null; then
                log_success "Service disabled"
            else
                log_warning "Failed to disable service, but continuing..."
            fi
        else
            log_info "Service is not enabled"
        fi
    else
        if sudo systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null; then
            if sudo systemctl stop "$SERVICE_FILE" 2>/dev/null; then
                log_success "Service stopped"
            else
                log_warning "Failed to stop service, but continuing..."
            fi
        else
            log_info "Service is not running"
        fi
        
        if sudo systemctl is-enabled --quiet "$SERVICE_FILE" 2>/dev/null; then
            if sudo systemctl disable "$SERVICE_FILE" 2>/dev/null; then
                log_success "Service disabled"
            else
                log_warning "Failed to disable service, but continuing..."
            fi
        else
            log_info "Service is not enabled"
        fi
    fi
}

# ============================================================================
# REMOVE SYSTEMD COMPONENTS
# ============================================================================

remove_systemd_components() {
    log_step "Removing systemd components..."
    
    # Remove certificate renewal timer
    if [ -f "/etc/systemd/system/$RENEWAL_TIMER_FILE" ]; then
        log_info "Removing certificate renewal timer..."
        if [ "$IS_ROOT" = true ]; then
            systemctl stop "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            systemctl disable "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            rm -f "/etc/systemd/system/$RENEWAL_TIMER_FILE" 2>/dev/null || true
        else
            sudo systemctl stop "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            sudo systemctl disable "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            sudo rm -f "/etc/systemd/system/$RENEWAL_TIMER_FILE" 2>/dev/null || true
        fi
        log_success "Certificate renewal timer removed"
    fi
    
    # Remove certificate renewal service
    if [ -f "/etc/systemd/system/$RENEWAL_SERVICE_FILE" ]; then
        log_info "Removing certificate renewal service..."
        if [ "$IS_ROOT" = true ]; then
            rm -f "/etc/systemd/system/$RENEWAL_SERVICE_FILE" 2>/dev/null || true
        else
            sudo rm -f "/etc/systemd/system/$RENEWAL_SERVICE_FILE" 2>/dev/null || true
        fi
        log_success "Certificate renewal service removed"
    fi
    
    # Remove main service
    if [ -f "/etc/systemd/system/$SERVICE_FILE" ]; then
        log_info "Removing main systemd service..."
        if [ "$IS_ROOT" = true ]; then
            rm -f "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null || true
        else
            sudo rm -f "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null || true
        fi
        log_success "Systemd service removed"
    else
        log_info "Service file not found"
    fi
    
    # Reload systemd daemon
    log_info "Reloading systemd daemon..."
    if [ "$IS_ROOT" = true ]; then
        if systemctl daemon-reload 2>/dev/null; then
            log_success "Systemd daemon reloaded"
        else
            log_warning "Failed to reload systemd daemon, but continuing..."
        fi
    else
        if sudo systemctl daemon-reload 2>/dev/null; then
            log_success "Systemd daemon reloaded"
        else
            log_warning "Failed to reload systemd daemon, but continuing..."
        fi
    fi
}

# ============================================================================
# REMOVE JOURNALD CONFIGURATION
# ============================================================================

remove_journald_config() {
    log_step "Removing journald configuration..."
    
    if [ -f "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" ]; then
        log_info "Removing journald configuration file..."
        if [ "$IS_ROOT" = true ]; then
            if rm -f "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" 2>/dev/null; then
                log_success "Journald configuration removed"
                # Restart journald to apply changes
                systemctl restart systemd-journald 2>/dev/null || log_warning "Failed to restart systemd-journald"
            else
                log_warning "Failed to remove journald configuration file"
            fi
        else
            if sudo rm -f "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" 2>/dev/null; then
                log_success "Journald configuration removed"
                # Restart journald to apply changes
                sudo systemctl restart systemd-journald 2>/dev/null || log_warning "Failed to restart systemd-journald"
            else
                log_warning "Failed to remove journald configuration file"
            fi
        fi
    else
        log_info "Journald configuration file not found"
    fi
}

# ============================================================================
# REMOVE DATA
# ============================================================================

remove_data() {
    log_step "Removing application data..."
    
    log_warning "This will remove all application data including:"
    log_warning "  - All IOCs (database)"
    log_warning "  - Uploaded files"
    log_warning "  - Generated outputs (STIX, reports)"
    log_warning "  - Database files"
    log_warning "  - Cache files"
    log_warning "  - SSL certificates"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Do you want to remove all application data? [y/N]: ${NC})" -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Data removal cancelled. Data will be preserved."
        return 0
    fi
    
    if [ -d "$INSTALL_DIR/cti-platform" ]; then
        log_info "Removing application data..."
        
        # Remove data directories
        local data_removed=false
        
        if [ -d "$INSTALL_DIR/cti-platform/uploads" ]; then
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/uploads"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/uploads"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        if [ -d "$INSTALL_DIR/cti-platform/outputs" ]; then
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/outputs"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/outputs"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        if [ -d "$INSTALL_DIR/cti-platform/database" ]; then
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/database"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/database"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        if [ -d "$INSTALL_DIR/cti-platform/modules/cache" ]; then
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/modules/cache"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/modules/cache"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        # Remove SSL certificates
        if [ -d "$INSTALL_DIR/cti-platform/ssl" ]; then
            log_info "Removing SSL certificates..."
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/ssl"/* 2>/dev/null || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/ssl"/* 2>/dev/null || true
            fi
        fi
        
        if [ "$data_removed" = true ]; then
            log_success "Application data removed"
        else
            log_info "No application data found to remove"
        fi
    else
        log_info "Installation directory not found. No data to remove."
    fi
}

# ============================================================================
# REMOVE INSTALLATION FILES
# ============================================================================

remove_files() {
    log_step "Removing installation files..."
    
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing all installation files including:"
        log_info "  - Application files (cti-platform/)"
        log_info "  - Python virtual environment (venv/)"
        log_info "  - Repositories (iocsearcher, txt2stix)"
        log_info "  - Requirements file"
        log_info "  - SSL certificate generation script"
        log_info "  - All caches and temporary files"
        echo ""
        
        read -p "$(echo -e ${YELLOW}Do you want to remove all installation files? [y/N]: ${NC})" -n 1 -r
        echo ""
        
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "File removal cancelled. Installation files will be preserved."
            return 0
        fi
        
        if [ "$IS_ROOT" = true ]; then
            if rm -rf "$INSTALL_DIR" 2>/dev/null; then
                log_success "Installation files removed"
            else
                log_error "Failed to remove installation directory"
                return 1
            fi
        else
            if sudo rm -rf "$INSTALL_DIR" 2>/dev/null; then
                log_success "Installation files removed"
            else
                log_error "Failed to remove installation directory"
                return 1
            fi
        fi
    else
        log_info "Installation directory not found: $INSTALL_DIR"
    fi
}

# ============================================================================
# REMOVE SERVICE USER
# ============================================================================

remove_service_user() {
    log_step "Removing service user and group..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        log_warning "Service user '$SERVICE_USER' exists."
        read -p "$(echo -e ${YELLOW}Do you want to remove the service user and group? [y/N]: ${NC})" -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ "$IS_ROOT" = true ]; then
                if userdel "$SERVICE_USER" 2>/dev/null; then
                    log_success "Service user removed"
                else
                    log_warning "Failed to remove service user, but continuing..."
                fi
            else
                if sudo userdel "$SERVICE_USER" 2>/dev/null; then
                    log_success "Service user removed"
                else
                    log_warning "Failed to remove service user, but continuing..."
                fi
            fi
            
            # Try to remove group if it exists and is not used
            if getent group "$SERVICE_GROUP" &>/dev/null; then
                if [ "$IS_ROOT" = true ]; then
                    groupdel "$SERVICE_GROUP" 2>/dev/null || log_info "Service group kept (may be in use)"
                else
                    sudo groupdel "$SERVICE_GROUP" 2>/dev/null || log_info "Service group kept (may be in use)"
                fi
            fi
        else
            log_info "Service user and group kept"
        fi
    else
        log_info "Service user does not exist"
        
        # Check if group exists without user
        if getent group "$SERVICE_GROUP" &>/dev/null; then
            log_info "Service group exists without user"
            read -p "$(echo -e ${YELLOW}Do you want to remove the service group? [y/N]: ${NC})" -n 1 -r
            echo ""
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if [ "$IS_ROOT" = true ]; then
                    groupdel "$SERVICE_GROUP" 2>/dev/null || log_info "Service group kept (may be in use)"
                else
                    sudo groupdel "$SERVICE_GROUP" 2>/dev/null || log_info "Service group kept (may be in use)"
                fi
            fi
        fi
    fi
}

# ============================================================================
# VERIFY UNINSTALLATION
# ============================================================================

verify_uninstallation() {
    log_step "Verifying uninstallation..."
    
    local issues=0
    
    # Check if service file still exists
    if [ -f "/etc/systemd/system/$SERVICE_FILE" ]; then
        log_warning "Service file still exists: /etc/systemd/system/$SERVICE_FILE"
        issues=$((issues + 1))
    fi
    
    # Check if installation directory still exists
    if [ -d "$INSTALL_DIR" ]; then
        log_warning "Installation directory still exists: $INSTALL_DIR"
        issues=$((issues + 1))
    fi
    
    # Check if service user still exists
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "Service user still exists: $SERVICE_USER (kept by user choice)"
    fi
    
    if [ $issues -eq 0 ]; then
        log_success "Uninstallation verified successfully"
        return 0
    else
        log_warning "Some components may still be present"
        return 1
    fi
}

# ============================================================================
# MAIN UNINSTALLATION FUNCTION
# ============================================================================

main() {
    echo ""
    echo -e "${MAGENTA}${BOLD}"
    cat << "EOF"
 OOO   DDDD   Y   Y  SSSSS    AAAAA  FFFFF   EEEEE
O   O  D   D   Y Y   S        A     A F       E
O   O  D   D   Y Y   SSSSS    AAAAAAA FFFF    EEEE
O   O  D   D   Y Y       S    A     A F       E
 OOO   DDDD    Y    SSSSS    A     A F       EEEEE

         Cyber Threat Intelligence Platform
EOF
    echo -e "${NC}"
    echo ""
    
    log_info "=========================================="
    log_info "Odysafe CTI Platform Uninstallation"
    log_info "=========================================="
    echo ""
    
    detect_environment
    
    # Check if installation exists
    if ! check_installation; then
        log_info "No installation found. Exiting."
        exit 0
    fi
    
    # Confirm uninstallation
    log_warning "This will uninstall Odysafe CTI Platform."
    log_warning "You will be asked to confirm removal of:"
    log_warning "  - Systemd service and timers"
    log_warning "  - Application data (IOCs, uploads, outputs)"
    log_warning "  - Installation files"
    log_warning "  - Service user (optional)"
    echo ""
    read -p "$(echo -e ${YELLOW}Are you sure you want to continue? [y/N]: ${NC})" -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
    
    # Stop service first
    stop_service
    
    # Remove systemd components
    remove_systemd_components
    
    # Remove journald configuration
    remove_journald_config
    
    # Remove data (with confirmation)
    remove_data
    
    # Remove installation files (with confirmation)
    remove_files
    
    # Remove service user (with confirmation)
    remove_service_user
    
    # Verify uninstallation
    verify_uninstallation
    
    echo ""
    log_success "=========================================="
    log_success "Uninstallation completed successfully!"
    log_success "=========================================="
    echo ""
    log_info "Odysafe CTI Platform has been removed from the system"
    echo ""
    log_info "Note: If you kept the service user or group, you can remove them manually:"
    if [ "$IS_ROOT" = true ]; then
        echo "  userdel $SERVICE_USER"
        echo "  groupdel $SERVICE_GROUP"
    else
        echo "  sudo userdel $SERVICE_USER"
        echo "  sudo groupdel $SERVICE_GROUP"
    fi
    echo ""
}

# Run main function
main
