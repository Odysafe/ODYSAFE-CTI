#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Uninstallation Script
# Complete uninstallation script for Odysafe CTI Platform
# This script removes everything created by install.sh
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

# Installation paths (must match install.sh, configurable via environment variables)
INSTALL_DIR="${CTI_INSTALL_DIR:-/opt/odysafe-cti-platform}"
SERVICE_USER="${CTI_SERVICE_USER:-odysafe-cti-platform}"
SERVICE_GROUP="${CTI_SERVICE_GROUP:-odysafe-cti-platform}"
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
    
    # Detect distribution (Debian/Ubuntu only)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
            log_error "Unsupported operating system: $ID"
            log_error "This application only supports Debian and Ubuntu."
            exit 1
        fi
        log_info "Distribution detected: $DISTRO"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        log_info "Distribution detected: Debian"
    else
        log_error "Could not detect a supported distribution."
        log_error "This application only supports Debian and Ubuntu."
        exit 1
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
    
    # Check for certificate renewal timer
    if [ -f "/etc/systemd/system/$RENEWAL_TIMER_FILE" ]; then
        log_info "Certificate renewal timer found: $RENEWAL_TIMER_FILE"
        found=true
    fi
    
    # Check for certificate renewal service
    if [ -f "/etc/systemd/system/$RENEWAL_SERVICE_FILE" ]; then
        log_info "Certificate renewal service found: $RENEWAL_SERVICE_FILE"
        found=true
    fi
    
    # Check for journald configuration
    if [ -f "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" ]; then
        log_info "Journald configuration found: $JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE"
        found=true
    fi
    
    if [ "$found" = false ]; then
        log_warning "No installation found. Nothing to uninstall."
        return 1
    fi
    
    return 0
}

# ============================================================================
# KILL PROCESSES USING PORT 5001
# ============================================================================

kill_port_processes() {
    local port="${CTI_PORT:-5001}"
    log_step "Killing processes using port $port..."
    
    local pids_to_kill=""
    local max_attempts=5
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))
        pids_to_kill=""
        port_in_use=false
        
        # Method 1: lsof (most reliable)
        if command -v lsof >/dev/null 2>&1; then
            PIDS_TO_KILL=$(lsof -ti:$PORT 2>/dev/null || true)
            if [ -n "$PIDS_TO_KILL" ]; then
                PORT_IN_USE=true
            fi
        fi
        
        # Method 2: ss (more modern than netstat)
        if [ -z "$PIDS_TO_KILL" ] && command -v ss >/dev/null 2>&1; then
            PIDS_TO_KILL=$(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1 || true)
            if [ -n "$PIDS_TO_KILL" ]; then
                PORT_IN_USE=true
            fi
        fi
        
        # Method 3: fuser
        if [ -z "$PIDS_TO_KILL" ] && command -v fuser >/dev/null 2>&1; then
            if [ "$IS_ROOT" = true ]; then
                FUSER_OUT=$(fuser $PORT/tcp 2>/dev/null || true)
            else
                FUSER_OUT=$(sudo fuser $PORT/tcp 2>/dev/null || true)
            fi
            if [ -n "$FUSER_OUT" ]; then
                PORT_IN_USE=true
                PIDS_TO_KILL=$(echo "$FUSER_OUT" | grep -oE '[0-9]+' | tr '\n' ' ' || true)
            fi
        fi
        
        # Method 4: netstat (fallback)
        if [ -z "$PIDS_TO_KILL" ] && command -v netstat >/dev/null 2>&1; then
            PID=$(netstat -tlnp 2>/dev/null | grep ":$PORT " | awk '{print $7}' | cut -d'/' -f1 | head -1 || true)
            if [ -n "$PID" ] && [ "$PID" != "-" ]; then
                PIDS_TO_KILL="$PID"
                PORT_IN_USE=true
            fi
        fi
        
        # Kill all found processes
        if [ -n "$PIDS_TO_KILL" ]; then
            log_info "Attempt $ATTEMPT: Killing process(es) using port $PORT: $PIDS_TO_KILL"
            for PID in $PIDS_TO_KILL; do
                if [ -n "$PID" ] && [ "$PID" != "-" ]; then
                    if [ "$IS_ROOT" = true ]; then
                        kill -9 "$PID" 2>/dev/null || true
                    else
                        sudo kill -9 "$PID" 2>/dev/null || true
                    fi
                fi
            done
            sleep 2
        fi
        
        # Also kill any Python processes running app.py (orphaned processes)
        if [ "$IS_ROOT" = true ]; then
            PYTHON_PIDS=$(ps aux 2>/dev/null | grep "[p]ython.*app.py" | awk '{print $2}' || true)
        else
            PYTHON_PIDS=$(sudo ps aux 2>/dev/null | grep "[p]ython.*app.py" | awk '{print $2}' || true)
        fi
        if [ -n "$PYTHON_PIDS" ]; then
            log_info "Killing orphaned Python processes: $PYTHON_PIDS"
            for PID in $PYTHON_PIDS; do
                if [ -n "$PID" ]; then
                    if [ "$IS_ROOT" = true ]; then
                        kill -9 "$PID" 2>/dev/null || true
                    else
                        sudo kill -9 "$PID" 2>/dev/null || true
                    fi
                fi
            done
            sleep 1
        fi
        
        # Use fuser to kill anything on port 5001
        if command -v fuser >/dev/null 2>&1; then
            if [ "$IS_ROOT" = true ]; then
                fuser -k $PORT/tcp 2>/dev/null || true
            else
                sudo fuser -k $PORT/tcp 2>/dev/null || true
            fi
            sleep 2
        fi
        
        # Check if port is now free
        if [ "$PORT_IN_USE" = false ] || [ -z "$PIDS_TO_KILL" ]; then
            # Verify port is actually free
            if command -v lsof >/dev/null 2>&1; then
                if [ -z "$(lsof -ti:$PORT 2>/dev/null || true)" ]; then
                    log_success "Port $PORT is now free"
                    break
                fi
            elif command -v ss >/dev/null 2>&1; then
                if [ -z "$(ss -tlnp 2>/dev/null | grep ":$PORT " || true)" ]; then
                    log_success "Port $PORT is now free"
                    break
                fi
            else
                # Assume it's free if we couldn't find any processes
                log_info "Port $PORT should be free (no verification tools available)"
                break
            fi
        fi
        
        if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
            log_warning "Could not free port $PORT after $MAX_ATTEMPTS attempts"
            log_warning "Port may still be in use. Continuing anyway..."
        fi
    done
}

# ============================================================================
# VERIFY PORT AVAILABILITY
# ============================================================================

verify_port_availability() {
    local port="${CTI_PORT:-5001}"
    log_step "Verifying port $port availability..."
    
    local port_free=true
    
    # Check with lsof
    if command -v lsof >/dev/null 2>&1; then
        if [ -n "$(lsof -ti:$port 2>/dev/null || true)" ]; then
            port_free=false
            log_warning "Port $port is still in use (detected via lsof)"
        fi
    fi
    
    # Check with ss
    if command -v ss >/dev/null 2>&1; then
        if [ -n "$(ss -tlnp 2>/dev/null | grep ":$port " || true)" ]; then
            port_free=false
            log_warning "Port $port is still in use (detected via ss)"
        fi
    fi
    
    # Check with netstat
    if command -v netstat >/dev/null 2>&1; then
        if [ -n "$(netstat -tlnp 2>/dev/null | grep ":$port " || true)" ]; then
            port_free=false
            log_warning "Port $port is still in use (detected via netstat)"
        fi
    fi
    
    if [ "$port_free" = true ]; then
        log_success "Port $port is available"
        return 0
    else
        log_warning "Port $port may still be in use"
        return 1
    fi
}

# ============================================================================
# STOP SERVICE
# ============================================================================

stop_service() {
    log_step "Stopping Odysafe CTI Platform service..."
    
    # Kill processes first
    kill_port_processes
    
    # Verify port is available
    verify_port_availability
    
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
        
        # Stop and disable certificate renewal timer
        if systemctl is-active --quiet "$RENEWAL_TIMER_FILE" 2>/dev/null; then
            systemctl stop "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            log_info "Certificate renewal timer stopped"
        fi
        if systemctl is-enabled --quiet "$RENEWAL_TIMER_FILE" 2>/dev/null; then
            systemctl disable "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            log_info "Certificate renewal timer disabled"
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
        
        # Stop and disable certificate renewal timer
        if sudo systemctl is-active --quiet "$RENEWAL_TIMER_FILE" 2>/dev/null; then
            sudo systemctl stop "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            log_info "Certificate renewal timer stopped"
        fi
        if sudo systemctl is-enabled --quiet "$RENEWAL_TIMER_FILE" 2>/dev/null; then
            sudo systemctl disable "$RENEWAL_TIMER_FILE" 2>/dev/null || true
            log_info "Certificate renewal timer disabled"
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
    else
        log_info "Certificate renewal timer not found"
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
    else
        log_info "Certificate renewal service not found"
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
# CLEAR CACHE
# ============================================================================

clear_cache() {
    log_step "Clearing technical caches (not user data)..."
    
    local cache_cleared=false
    
    if [ -d "$INSTALL_DIR/cti-platform" ]; then
        # Clear application technical cache (parsed data, temporary files)
        # Note: User favorites and manual sources are considered user data and kept in remove_data()
        if [ -d "$INSTALL_DIR/cti-platform/modules/cache" ]; then
            log_info "Clearing technical application cache (parsed data, temp files)..."
            if [ "$IS_ROOT" = true ]; then
                # Only remove technical cache, keep user preferences
                find "$INSTALL_DIR/cti-platform/modules/cache" -type f \( -name "*_cache.json" -o -name "*_parsed.json" \) -delete 2>/dev/null && cache_cleared=true || true
                find "$INSTALL_DIR/cti-platform/modules/cache" -type d -empty -delete 2>/dev/null || true
            else
                sudo find "$INSTALL_DIR/cti-platform/modules/cache" -type f \( -name "*_cache.json" -o -name "*_parsed.json" \) -delete 2>/dev/null && cache_cleared=true || true
                sudo find "$INSTALL_DIR/cti-platform/modules/cache" -type d -empty -delete 2>/dev/null || true
            fi
        fi
        
        # Clear Python cache (__pycache__, .pyc files) - technical only
        log_info "Clearing Python bytecode cache files..."
        if [ "$IS_ROOT" = true ]; then
            find "$INSTALL_DIR/cti-platform" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null && cache_cleared=true || true
            find "$INSTALL_DIR/cti-platform" -type f -name "*.pyc" -delete 2>/dev/null || true
            find "$INSTALL_DIR/cti-platform" -type f -name "*.pyo" -delete 2>/dev/null || true
        else
            sudo find "$INSTALL_DIR/cti-platform" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null && cache_cleared=true || true
            sudo find "$INSTALL_DIR/cti-platform" -type f -name "*.pyc" -delete 2>/dev/null || true
            sudo find "$INSTALL_DIR/cti-platform" -type f -name "*.pyo" -delete 2>/dev/null || true
        fi
        
        # Clear virtual environment cache if it exists
        if [ -d "$INSTALL_DIR/venv" ]; then
            log_info "Clearing virtual environment bytecode cache..."
            if [ "$IS_ROOT" = true ]; then
                find "$INSTALL_DIR/venv" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
                find "$INSTALL_DIR/venv" -type f -name "*.pyc" -delete 2>/dev/null || true
                find "$INSTALL_DIR/venv" -type f -name "*.pyo" -delete 2>/dev/null || true
            else
                sudo find "$INSTALL_DIR/venv" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
                sudo find "$INSTALL_DIR/venv" -type f -name "*.pyc" -delete 2>/dev/null || true
                sudo find "$INSTALL_DIR/venv" -type f -name "*.pyo" -delete 2>/dev/null || true
            fi
        fi
        
        # Clear pip cache
        if [ -d "$INSTALL_DIR/.pip_cache" ]; then
            log_info "Clearing pip cache..."
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/.pip_cache" 2>/dev/null && cache_cleared=true || true
            else
                sudo rm -rf "$INSTALL_DIR/.pip_cache" 2>/dev/null && cache_cleared=true || true
            fi
        fi
        
        if [ "$cache_cleared" = true ]; then
            log_success "Technical caches cleared"
        else
            log_info "No technical cache files found to clear"
        fi
    else
        log_info "Installation directory not found. No cache to clear."
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
    log_warning "  - Generated outputs (STIX, reports, PDF analyses)"
    log_warning "  - Database files"
    log_warning "  - Cache files"
    log_warning "  - SSL certificates"
    log_warning "  - deepdarkCTI repository"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Do you want to remove all application data? [y/N]: ${NC})" -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Data removal cancelled. Data will be preserved."
        return 0
    fi
    
    if [ -d "$INSTALL_DIR/cti-platform" ]; then
        log_info "Removing application data..."
        
        # Clear cache first
        clear_cache
        
        # Remove data directories
        local data_removed=false
        
        # Remove uploads
        if [ -d "$INSTALL_DIR/cti-platform/uploads" ]; then
            log_info "Removing uploaded files..."
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/uploads"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/uploads"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        # Remove outputs (iocs, stix, reports)
        if [ -d "$INSTALL_DIR/cti-platform/outputs" ]; then
            log_info "Removing output files..."
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/outputs"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/outputs"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        # Remove database
        if [ -d "$INSTALL_DIR/cti-platform/database" ]; then
            log_info "Removing database files..."
            if [ "$IS_ROOT" = true ]; then
                rm -f "$INSTALL_DIR/cti-platform/database"/*.db 2>/dev/null || true
                rm -f "$INSTALL_DIR/cti-platform/database"/*.db-shm 2>/dev/null || true
                rm -f "$INSTALL_DIR/cti-platform/database"/*.db-wal 2>/dev/null || true
                rm -rf "$INSTALL_DIR/cti-platform/database"/* 2>/dev/null && data_removed=true || true
            else
                sudo rm -f "$INSTALL_DIR/cti-platform/database"/*.db 2>/dev/null || true
                sudo rm -f "$INSTALL_DIR/cti-platform/database"/*.db-shm 2>/dev/null || true
                sudo rm -f "$INSTALL_DIR/cti-platform/database"/*.db-wal 2>/dev/null || true
                sudo rm -rf "$INSTALL_DIR/cti-platform/database"/* 2>/dev/null && data_removed=true || true
            fi
        fi
        
        # Remove cache directory completely
        if [ -d "$INSTALL_DIR/cti-platform/modules/cache" ]; then
            log_info "Removing cache directory..."
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/modules/cache" 2>/dev/null && data_removed=true || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/modules/cache" 2>/dev/null && data_removed=true || true
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
        
        # Remove deepdarkCTI repository
        if [ -d "$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main" ]; then
            log_info "Removing deepdarkCTI repository..."
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main" 2>/dev/null || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main" 2>/dev/null || true
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
        log_info "  - Repositories (iocsearcher)"
        log_info "  - Requirements file"
        log_info "  - SSL certificate generation script (generate-ssl-cert.sh)"
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
                log_warning "Some files may still exist. You may need to remove them manually."
                return 1
            fi
        else
            if sudo rm -rf "$INSTALL_DIR" 2>/dev/null; then
                log_success "Installation files removed"
            else
                log_error "Failed to remove installation directory"
                log_warning "Some files may still exist. You may need to remove them manually."
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
    
    # Check if certificate renewal timer still exists
    if [ -f "/etc/systemd/system/$RENEWAL_TIMER_FILE" ]; then
        log_warning "Certificate renewal timer still exists: /etc/systemd/system/$RENEWAL_TIMER_FILE"
        issues=$((issues + 1))
    fi
    
    # Check if certificate renewal service still exists
    if [ -f "/etc/systemd/system/$RENEWAL_SERVICE_FILE" ]; then
        log_warning "Certificate renewal service still exists: /etc/systemd/system/$RENEWAL_SERVICE_FILE"
        issues=$((issues + 1))
    fi
    
    # Check if installation directory still exists
    if [ -d "$INSTALL_DIR" ]; then
        log_warning "Installation directory still exists: $INSTALL_DIR"
        issues=$((issues + 1))
    fi
    
    # Check if journald configuration still exists
    if [ -f "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" ]; then
        log_warning "Journald configuration still exists: $JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE"
        issues=$((issues + 1))
    fi
    
    # Check if service user still exists
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "Service user still exists: $SERVICE_USER (kept by user choice)"
    fi
    
    # Check port availability
    local port="${CTI_PORT:-5001}"
    if verify_port_availability; then
        log_success "Port $port is available"
    else
        log_warning "Port $port may still be in use"
        issues=$((issues + 1))
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
    log_warning "  - Certificate renewal timer and service"
    log_warning "  - Journald configuration"
    log_warning "  - Application data (IOCs, uploads, outputs, PDF analyses)"
    log_warning "  - Installation files (application, venv, repositories)"
    log_warning "  - SSL certificates and generation script"
    log_warning "  - deepdarkCTI repository"
    log_warning "  - Service user (optional)"
    echo ""
    read -p "$(echo -e ${YELLOW}Are you sure you want to continue? [y/N]: ${NC})" -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
    
    # Stop service first and verify it's stopped
    stop_service
    
    # Wait a moment for processes to fully terminate
    sleep 2
    
    # Verify port is available before proceeding
    log_step "Verifying port availability..."
    CTI_PORT="${CTI_PORT:-5001}"
    if ! verify_port_availability; then
        log_warning "Port $CTI_PORT may still be in use"
        log_info "Waiting additional time for processes to terminate..."
        sleep 3
        if ! verify_port_availability; then
            log_warning "Port $CTI_PORT still appears in use. Proceeding with caution."
        fi
    fi
    
    # Clear cache (always done, no confirmation needed - this is technical cache)
    clear_cache
    
    # Remove systemd components
    remove_systemd_components
    
    # Remove journald configuration
    remove_journald_config
    
    # Remove data (with confirmation - this is user data)
    remove_data
    
    # Remove installation files (with confirmation)
    remove_files
    
    # Remove service user (with confirmation)
    remove_service_user
    
    # Final port verification
    log_step "Final port verification..."
    if verify_port_availability; then
        log_success "Port $CTI_PORT is confirmed available"
    else
        log_warning "Port $CTI_PORT may still be in use. You may need to manually check and free it."
    fi
    
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
