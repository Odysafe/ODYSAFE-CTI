#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Installation Script
# Complete installation script for Odysafe CTI Platform as a systemd service
# ============================================================================

set -e  # Stop on error

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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Global variables for environment detection
IS_ROOT=false
HAS_SUDO=false
DISTRO=""
PKG_MANAGER=""
PYTHON_CMD=""
PIP_CMD=""
PYTHON_VERSION=""
PYTHON_MAJOR=0
PYTHON_MINOR=0
INSTALL_CMD=""

# ============================================================================
# LOGO ASCII ART
# ============================================================================

show_logo() {
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
}

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
        log_info "Distribution detected: $DISTRO ($VERSION)"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        log_info "Distribution detected: Debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        log_info "Distribution detected: Red Hat based"
    else
        DISTRO="unknown"
        log_warning "Could not detect distribution, assuming Debian/Ubuntu"
    fi
    
    # Detect package manager
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
        log_info "Package manager: apt"
    elif command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        log_info "Package manager: apt-get"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        log_info "Package manager: dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        log_info "Package manager: yum"
    else
        log_error "No supported package manager found (apt, apt-get, dnf, yum)"
        exit 1
    fi
    
    # Set install command based on root/sudo
    if [ "$IS_ROOT" = true ]; then
        INSTALL_CMD="$PKG_MANAGER install -y"
    else
        INSTALL_CMD="sudo $PKG_MANAGER install -y"
    fi
    
    log_success "Environment detection complete"
}

# ============================================================================
# PYTHON DETECTION
# ============================================================================

detect_python() {
    log_step "Detecting Python installation..."
    
    # Try to find Python 3 (check multiple versions)
    PYTHON_VERSIONS=("python3.13" "python3.12" "python3.11" "python3.10" "python3.9" "python3.8" "python3.7" "python3.6" "python3")
    
    for py_cmd in "${PYTHON_VERSIONS[@]}"; do
        if command -v "$py_cmd" &> /dev/null; then
            PYTHON_CMD="$py_cmd"
            PYTHON_VERSION=$($py_cmd --version 2>&1 | cut -d' ' -f2)
            
            # Extract major and minor version
            PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
            PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
            
            log_info "Python found: $PYTHON_CMD (version $PYTHON_VERSION)"
            
            # Check minimum version (3.8)
            if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
                log_warning "Python version $PYTHON_VERSION is below minimum required (3.8)"
                continue
            fi
            
            log_success "Python $PYTHON_VERSION detected and compatible"
            return 0
        fi
    done
    
    log_error "Python 3.8+ not found"
    return 1
}

detect_pip() {
    log_step "Detecting pip installation..."
    
    # Try different pip commands
    if [ -n "$PYTHON_CMD" ]; then
        if $PYTHON_CMD -m pip --version &> /dev/null; then
            PIP_CMD="$PYTHON_CMD -m pip"
            log_success "pip found: $PIP_CMD"
            return 0
        fi
    fi
    
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
        log_success "pip found: pip3"
        return 0
    fi
    
    if command -v pip &> /dev/null; then
        PIP_CMD="pip"
        log_success "pip found: pip"
        return 0
    fi
    
    log_warning "pip not found"
    return 1
}

# ============================================================================
# PREREQUISITES CHECK
# ============================================================================

MISSING_PACKAGES=()
MISSING_COMMANDS=()

check_prerequisites() {
    log_step "Checking prerequisites..."
    
    MISSING_PACKAGES=()
    MISSING_COMMANDS=()
    
    # Check Python
    if ! detect_python; then
        MISSING_COMMANDS+=("python3 (>=3.8)")
        case "$DISTRO" in
            debian|ubuntu)
                MISSING_PACKAGES+=("python3")
                ;;
            rhel|centos|fedora)
                MISSING_PACKAGES+=("python3")
                ;;
        esac
    fi
    
    # Check pip
    if ! detect_pip; then
        MISSING_COMMANDS+=("pip")
        case "$DISTRO" in
            debian|ubuntu)
                MISSING_PACKAGES+=("python3-pip")
                ;;
            rhel|centos|fedora)
                MISSING_PACKAGES+=("python3-pip")
                ;;
        esac
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        MISSING_COMMANDS+=("git")
        MISSING_PACKAGES+=("git")
    else
        log_info "git: $(git --version)"
    fi
    
    # Check systemd
    if ! command -v systemctl &> /dev/null; then
        MISSING_COMMANDS+=("systemd")
        log_error "systemd is required but not found"
        exit 1
    else
        log_info "systemd: available"
    fi
    
    # Check python3-venv (need version-specific package on Debian/Ubuntu)
    if [ -n "$PYTHON_CMD" ]; then
        # Try to create a test venv to check if ensurepip is available
        TEST_VENV_DIR="/tmp/test_venv_$$"
        if $PYTHON_CMD -m venv "$TEST_VENV_DIR" &> /dev/null; then
            rm -rf "$TEST_VENV_DIR"
            log_info "python3-venv: available"
        else
            MISSING_COMMANDS+=("python3-venv")
            case "$DISTRO" in
                debian|ubuntu)
                    # Get Python version (e.g., 3.11) and check for version-specific package
                    PYTHON_VERSION_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)
                    PYTHON_VENV_PKG="python${PYTHON_VERSION_MINOR}-venv"
                    # Check if version-specific package is installed
                    if ! dpkg -l | grep -q "^ii.*${PYTHON_VENV_PKG}"; then
                        MISSING_PACKAGES+=("$PYTHON_VENV_PKG")
                        log_info "Need version-specific package: $PYTHON_VENV_PKG"
                    fi
                    # Also check generic python3-venv as fallback
                    if ! dpkg -l | grep -q "^ii.*python3-venv"; then
                        if [[ ! " ${MISSING_PACKAGES[@]} " =~ " ${PYTHON_VENV_PKG} " ]]; then
                            MISSING_PACKAGES+=("python3-venv")
                        fi
                    fi
                    ;;
                rhel|centos|fedora)
                    MISSING_PACKAGES+=("python3-devel")
                    ;;
            esac
        fi
    fi
    
    # Check build tools (for compiling Python packages)
    case "$DISTRO" in
        debian|ubuntu)
            if ! dpkg -l | grep -q "build-essential"; then
                MISSING_PACKAGES+=("build-essential")
            fi
            if ! dpkg -l | grep -q "python3-dev"; then
                MISSING_PACKAGES+=("python3-dev")
            fi
            # Check libmagic (required for python-magic)
            if ! dpkg -l | grep -q "libmagic1"; then
                MISSING_PACKAGES+=("libmagic1")
            fi
            if ! dpkg -l | grep -q "libmagic-dev"; then
                MISSING_PACKAGES+=("libmagic-dev")
            fi
            # Check libxml2 and libxslt (required for lxml)
            if ! dpkg -l | grep -q "libxml2-dev"; then
                MISSING_PACKAGES+=("libxml2-dev")
            fi
            if ! dpkg -l | grep -q "libxslt1-dev"; then
                MISSING_PACKAGES+=("libxslt1-dev")
            fi
            # Check libffi (required for some Python packages)
            if ! dpkg -l | grep -q "libffi-dev"; then
                MISSING_PACKAGES+=("libffi-dev")
            fi
            # Check libssl (required for SSL support in Python)
            if ! dpkg -l | grep -q "libssl-dev"; then
                MISSING_PACKAGES+=("libssl-dev")
            fi
            # Check zlib (required for compression)
            if ! dpkg -l | grep -q "zlib1g-dev"; then
                MISSING_PACKAGES+=("zlib1g-dev")
            fi
            ;;
        rhel|centos|fedora)
            if ! rpm -qa | grep -q "gcc"; then
                MISSING_PACKAGES+=("gcc")
            fi
            if ! rpm -qa | grep -q "python3-devel"; then
                MISSING_PACKAGES+=("python3-devel")
            fi
            # Check file-devel (required for python-magic)
            if ! rpm -qa | grep -q "file-devel"; then
                MISSING_PACKAGES+=("file-devel")
            fi
            # Check libxml2 and libxslt (required for lxml)
            if ! rpm -qa | grep -q "libxml2-devel"; then
                MISSING_PACKAGES+=("libxml2-devel")
            fi
            if ! rpm -qa | grep -q "libxslt-devel"; then
                MISSING_PACKAGES+=("libxslt-devel")
            fi
            # Check libffi (required for some Python packages)
            if ! rpm -qa | grep -q "libffi-devel"; then
                MISSING_PACKAGES+=("libffi-devel")
            fi
            # Check openssl-devel (required for SSL support in Python)
            if ! rpm -qa | grep -q "openssl-devel"; then
                MISSING_PACKAGES+=("openssl-devel")
            fi
            # Check zlib-devel (required for compression)
            if ! rpm -qa | grep -q "zlib-devel"; then
                MISSING_PACKAGES+=("zlib-devel")
            fi
            ;;
    esac
    
    # Check openssl (for SSL certificate generation)
    if ! command -v openssl &> /dev/null; then
        MISSING_COMMANDS+=("openssl")
        case "$DISTRO" in
            debian|ubuntu)
                MISSING_PACKAGES+=("openssl")
                ;;
            rhel|centos|fedora)
                MISSING_PACKAGES+=("openssl")
                ;;
        esac
    else
        log_info "openssl: $(openssl version | cut -d' ' -f1-2)"
    fi
    
    # Display results
    if [ ${#MISSING_COMMANDS[@]} -eq 0 ] && [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
        log_success "All prerequisites are installed"
        return 0
    else
        return 1
    fi
}

display_missing() {
    echo ""
    log_warning "=========================================="
    log_warning "Missing Prerequisites Detected"
    log_warning "=========================================="
    echo ""
    
    if [ ${#MISSING_COMMANDS[@]} -gt 0 ]; then
        log_info "Missing commands/tools:"
        for cmd in "${MISSING_COMMANDS[@]}"; do
            echo -e "  ${YELLOW}✗${NC} $cmd"
        done
        echo ""
    fi
    
    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
        log_info "Missing packages to install:"
        for pkg in "${MISSING_PACKAGES[@]}"; do
            echo -e "  ${YELLOW}✗${NC} $pkg"
        done
        echo ""
    fi
    
    log_info "The following packages will be installed:"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        echo -e "  ${CYAN}→${NC} $pkg"
    done
    echo ""
    
    read -p "$(echo -e ${YELLOW}Do you want to install the missing prerequisites? [Y/n]: ${NC})" -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_error "Installation cancelled by user"
        exit 1
    fi
    
    # Default to yes if Enter pressed
    log_info "Proceeding with installation..."
}

install_prerequisites() {
    if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
        return 0
    fi
    
    log_step "Installing missing prerequisites..."
    
    # Update package list
    if [ "$PKG_MANAGER" = "apt" ] || [ "$PKG_MANAGER" = "apt-get" ]; then
        log_info "Updating package list..."
        if [ "$IS_ROOT" = true ]; then
            $PKG_MANAGER update
        else
            sudo $PKG_MANAGER update
        fi
    fi
    
    # Install packages
    log_info "Installing packages: ${MISSING_PACKAGES[*]}"
    $INSTALL_CMD "${MISSING_PACKAGES[@]}"
    
    # Re-detect Python and pip after installation
    if ! detect_python; then
        log_error "Python installation failed"
        exit 1
    fi
    
    if ! detect_pip; then
        log_error "pip installation failed"
        exit 1
    fi
    
    log_success "Prerequisites installed successfully"
}

# ============================================================================
# SERVICE USER CREATION
# ============================================================================

create_service_user() {
    log_step "Creating service user and group..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        if [ "$IS_ROOT" = true ]; then
            useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        else
            sudo useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        fi
        log_success "Service user created: $SERVICE_USER"
    else
        log_info "Service user already exists: $SERVICE_USER"
    fi
}

# ============================================================================
# INSTALL APPLICATION FILES
# ============================================================================

install_files() {
    log_step "Installing application files to $INSTALL_DIR..."
    
    # Create installation directory
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$INSTALL_DIR"
    else
        sudo mkdir -p "$INSTALL_DIR"
    fi
    
    # Check if this is a reinstallation (preserve data)
    PRESERVE_DATA=false
    if [ -d "$INSTALL_DIR/cti-platform" ]; then
        PRESERVE_DATA=true
        log_info "Existing installation detected. Preserving data (IOCs, uploads, outputs)..."
        
        # Backup data directories
        TEMP_BACKUP="/tmp/odysafe-cti-backup-$$"
        mkdir -p "$TEMP_BACKUP"
        
        # Backup database
        if [ -d "$INSTALL_DIR/cti-platform/database" ]; then
            cp -r "$INSTALL_DIR/cti-platform/database" "$TEMP_BACKUP/" 2>/dev/null || true
            log_info "Database backed up"
        fi
        
        # Backup uploads (user data)
        if [ -d "$INSTALL_DIR/cti-platform/uploads" ]; then
            cp -r "$INSTALL_DIR/cti-platform/uploads" "$TEMP_BACKUP/" 2>/dev/null || true
            log_info "Uploads backed up"
        fi
        
        # Backup outputs (user data)
        if [ -d "$INSTALL_DIR/cti-platform/outputs" ]; then
            cp -r "$INSTALL_DIR/cti-platform/outputs" "$TEMP_BACKUP/" 2>/dev/null || true
            log_info "Outputs backed up"
        fi
        
        # Backup modules/cache (user preferences)
        if [ -d "$INSTALL_DIR/cti-platform/modules/cache" ]; then
            cp -r "$INSTALL_DIR/cti-platform/modules/cache" "$TEMP_BACKUP/" 2>/dev/null || true
            log_info "Cache backed up"
        fi
        
        # Remove old installation (except venv which will be recreated)
        if [ -d "$INSTALL_DIR/cti-platform" ]; then
            rm -rf "$INSTALL_DIR/cti-platform"
        fi
        if [ -d "$INSTALL_DIR/repos" ]; then
            rm -rf "$INSTALL_DIR/repos"
        fi
        if [ -f "$INSTALL_DIR/requirements.txt" ]; then
            rm -f "$INSTALL_DIR/requirements.txt"
        fi
    fi
    
    # Copy new files
    cp -r "$SCRIPT_DIR/cti-platform" "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR/repos" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
    
    # Restore data if this was a reinstallation
    if [ "$PRESERVE_DATA" = true ] && [ -d "$TEMP_BACKUP" ]; then
        log_info "Restoring user data..."
        
        # Restore database
        if [ -d "$TEMP_BACKUP/database" ]; then
            if [ "$IS_ROOT" = true ]; then
                cp -r "$TEMP_BACKUP/database"/* "$INSTALL_DIR/cti-platform/database/" 2>/dev/null || true
            else
                sudo cp -r "$TEMP_BACKUP/database"/* "$INSTALL_DIR/cti-platform/database/" 2>/dev/null || true
            fi
            log_info "Database restored"
        fi
        
        # Restore uploads
        if [ -d "$TEMP_BACKUP/uploads" ]; then
            if [ "$IS_ROOT" = true ]; then
                cp -r "$TEMP_BACKUP/uploads"/* "$INSTALL_DIR/cti-platform/uploads/" 2>/dev/null || true
            else
                sudo cp -r "$TEMP_BACKUP/uploads"/* "$INSTALL_DIR/cti-platform/uploads/" 2>/dev/null || true
            fi
            log_info "Uploads restored"
        fi
        
        # Restore outputs
        if [ -d "$TEMP_BACKUP/outputs" ]; then
            if [ "$IS_ROOT" = true ]; then
                cp -r "$TEMP_BACKUP/outputs"/* "$INSTALL_DIR/cti-platform/outputs/" 2>/dev/null || true
            else
                sudo cp -r "$TEMP_BACKUP/outputs"/* "$INSTALL_DIR/cti-platform/outputs/" 2>/dev/null || true
            fi
            log_info "Outputs restored"
        fi
        
        # Restore cache
        if [ -d "$TEMP_BACKUP/cache" ]; then
            if [ "$IS_ROOT" = true ]; then
                cp -r "$TEMP_BACKUP/cache"/* "$INSTALL_DIR/cti-platform/modules/cache/" 2>/dev/null || true
            else
                sudo cp -r "$TEMP_BACKUP/cache"/* "$INSTALL_DIR/cti-platform/modules/cache/" 2>/dev/null || true
            fi
            log_info "Cache restored"
        fi
        
        # Cleanup backup
        rm -rf "$TEMP_BACKUP"
        log_success "User data preserved and restored"
    fi
    
    # Set ownership
    if [ "$IS_ROOT" = true ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    else
        sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    fi
    
    log_success "Application files installed"
}

# ============================================================================
# PYTHON ENVIRONMENT SETUP
# ============================================================================

setup_python_environment() {
    log_step "Setting up Python virtual environment..."
    
    cd "$INSTALL_DIR"
    
    # Remove existing venv if present
    if [ -d "venv" ]; then
        log_info "Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Ensure python3-venv package is installed (version-specific for Debian/Ubuntu)
    if [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
        PYTHON_VERSION_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)
        PYTHON_VENV_PKG="python${PYTHON_VERSION_MINOR}-venv"
        
        # Check if version-specific package is installed
        if ! dpkg -l | grep -q "^ii.*${PYTHON_VENV_PKG}"; then
            log_info "Installing $PYTHON_VENV_PKG package..."
            if [ "$IS_ROOT" = true ]; then
                if $INSTALL_CMD install -y "$PYTHON_VENV_PKG" 2>&1; then
                    log_success "$PYTHON_VENV_PKG installed"
                else
                    log_warning "Failed to install $PYTHON_VENV_PKG, trying python3-venv..."
                    if $INSTALL_CMD install -y python3-venv 2>&1; then
                        log_success "python3-venv installed"
                    else
                        log_error "Failed to install python3-venv package"
                        log_error "Please install $PYTHON_VENV_PKG manually: $INSTALL_CMD $PYTHON_VENV_PKG"
                        exit 1
                    fi
                fi
            else
                if sudo $INSTALL_CMD install -y "$PYTHON_VENV_PKG" 2>&1; then
                    log_success "$PYTHON_VENV_PKG installed"
                else
                    log_warning "Failed to install $PYTHON_VENV_PKG, trying python3-venv..."
                    if sudo $INSTALL_CMD install -y python3-venv 2>&1; then
                        log_success "python3-venv installed"
                    else
                        log_error "Failed to install python3-venv package"
                        log_error "Please install $PYTHON_VENV_PKG manually: sudo $INSTALL_CMD $PYTHON_VENV_PKG"
                        exit 1
                    fi
                fi
            fi
        fi
    fi
    
    # Create virtual environment using detected Python
    log_info "Creating virtual environment with $PYTHON_CMD..."
    VENV_OUTPUT=$(sudo -u "$SERVICE_USER" $PYTHON_CMD -m venv venv 2>&1)
    VENV_EXIT_CODE=$?
    
    if [ $VENV_EXIT_CODE -eq 0 ]; then
        log_success "Virtual environment created"
    else
        log_error "Failed to create virtual environment"
        echo "$VENV_OUTPUT" | while IFS= read -r line; do
            log_error "$line"
        done
        
        # Try to provide helpful error message
        if echo "$VENV_OUTPUT" | grep -q "ensurepip is not available"; then
            PYTHON_VERSION_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)
            log_error ""
            log_error "The python3-venv package is missing or incomplete."
            if [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
                log_error "On Debian/Ubuntu, you need to install: python${PYTHON_VERSION_MINOR}-venv"
                log_error "Run: $INSTALL_CMD python${PYTHON_VERSION_MINOR}-venv"
            else
                log_error "Please install the python3-venv package for your distribution."
            fi
        fi
        exit 1
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip, setuptools, wheel
    log_info "Upgrading pip, setuptools, wheel..."
    $PIP_CMD install --upgrade pip setuptools wheel --quiet
    
    # Install main dependencies
    log_info "Installing main dependencies from requirements.txt..."
    $PIP_CMD install -r requirements.txt --quiet
    
    # Configure iocsearcher from local repository (already included in package)
    if [ -d "repos/iocsearcher-main" ]; then
        log_info "Configuring iocsearcher from local repository..."
        $PIP_CMD install -e repos/iocsearcher-main --quiet
        log_success "iocsearcher configured"
    else
        log_error "iocsearcher repository not found in repos/iocsearcher-main"
        log_error "The package is incomplete. Please ensure repos/iocsearcher-main is present."
        exit 1
    fi
    
    # Configure txt2stix from local repository (already included in package)
    if [ -d "repos/txt2stix-main" ]; then
        log_info "Configuring txt2stix from local repository..."
        
        # Install txt2stix dependencies first if requirements.txt exists
        if [ -f "repos/txt2stix-main/requirements.txt" ]; then
            $PIP_CMD install -r repos/txt2stix-main/requirements.txt --quiet
        fi
        
        # Install txt2stix from its directory (needed for includes path resolution)
        # Change to txt2stix directory so includes/ is found correctly
        TXT2STIX_DIR="$INSTALL_DIR/repos/txt2stix-main"
        cd "$TXT2STIX_DIR"
        $PIP_CMD install -e . --quiet
        cd "$INSTALL_DIR"
        log_success "txt2stix configured"
    else
        log_error "txt2stix repository not found in repos/txt2stix-main"
        log_error "The package is incomplete. Please ensure repos/txt2stix-main is present."
        exit 1
    fi
    
    # Set ownership
    if [ "$IS_ROOT" = true ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" venv
    else
        sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" venv
    fi
    
    log_success "Python environment setup complete"
}

# ============================================================================
# CREATE DIRECTORIES
# ============================================================================

create_directories() {
    log_step "Creating necessary directories..."
    
    cd "$INSTALL_DIR/cti-platform"
    
    mkdir -p uploads
    mkdir -p outputs/iocs
    mkdir -p outputs/stix
    mkdir -p outputs/reports
    mkdir -p database
    mkdir -p modules/cache
    mkdir -p ssl
    
    # Set ownership
    if [ "$IS_ROOT" = true ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" uploads outputs database modules/cache ssl
    else
        sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" uploads outputs database modules/cache ssl
    fi
    
    log_success "Directories created"
}

# ============================================================================
# DOWNLOAD DEEPDARKCTI
# ============================================================================

download_deepdarkcti() {
    # This function is kept for backward compatibility but is no longer called automatically
    # The repository should be downloaded manually via the web interface (Download or Refresh button)
    log_step "Downloading deepdarkCTI repository..."
    
    DEEPDARKCTI_REPO_URL="https://github.com/fastfire/deepdarkCTI.git"
    DEEPDARKCTI_DIR="$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main"
    
    if [ -d "$DEEPDARKCTI_DIR" ]; then
        log_info "Removing existing deepdarkCTI repository..."
        rm -rf "$DEEPDARKCTI_DIR"
    fi
    
    # Download as service user
    if [ "$IS_ROOT" = true ]; then
        if sudo -u "$SERVICE_USER" git clone "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" 2>/dev/null; then
            log_success "deepdarkCTI repository downloaded"
        else
            log_warning "Unable to download deepdarkCTI repository. It can be downloaded later via the web interface."
        fi
    else
        if sudo -u "$SERVICE_USER" git clone "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" 2>/dev/null; then
            log_success "deepdarkCTI repository downloaded"
        else
            log_warning "Unable to download deepdarkCTI repository. It can be downloaded later via the web interface."
        fi
    fi
}

# ============================================================================
# GENERATE SSL CERTIFICATE
# ============================================================================

generate_ssl_certificate() {
    log_step "Setting up SSL/TLS certificate..."
    
    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        log_warning "OpenSSL is not installed. SSL certificate generation skipped."
        log_info "Install OpenSSL: $INSTALL_CMD openssl"
        return 0
    fi
    
    SSL_DIR="$INSTALL_DIR/cti-platform/ssl"
    CERT_FILE="$SSL_DIR/cert.pem"
    KEY_FILE="$SSL_DIR/key.pem"
    
    # Check if certificate already exists
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        # Check certificate expiration
        EXPIRY_DATE=$(openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "$EXPIRY_DATE" ]; then
            EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y" "$EXPIRY_DATE" +%s 2>/dev/null || echo "0")
            CURRENT_EPOCH=$(date +%s)
            DAYS_UNTIL_EXPIRY=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))
            
            if [ "$DAYS_UNTIL_EXPIRY" -gt 30 ]; then
                log_info "SSL certificate already exists and is valid for $DAYS_UNTIL_EXPIRY more days"
                log_info "Certificate expires on: $EXPIRY_DATE"
                return 0
            else
                log_info "SSL certificate expires soon ($DAYS_UNTIL_EXPIRY days). Regenerating..."
            fi
        fi
    fi
    
    # Get hostname or IP
    HOSTNAME=$(hostname -f 2>/dev/null || hostname || echo "localhost")
    IP_ADDRESS=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.0.1")
    
    log_info "Generating self-signed SSL certificate..."
    log_info "Hostname: $HOSTNAME"
    log_info "IP Address: $IP_ADDRESS"
    log_info "Valid for: 1 year (365 days)"
    
    # Generate certificate
    if [ "$IS_ROOT" = true ]; then
        openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
            -days 365 -nodes \
            -subj "/C=FR/ST=France/L=Paris/O=Odysafe/OU=CTI Platform/CN=$HOSTNAME" \
            -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:$IP_ADDRESS,IP:127.0.0.1" \
            2>/dev/null
    else
        sudo openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
            -days 365 -nodes \
            -subj "/C=FR/ST=France/L=Paris/O=Odysafe/OU=CTI Platform/CN=$HOSTNAME" \
            -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:$IP_ADDRESS,IP:127.0.0.1" \
            2>/dev/null
    fi
    
    if [ $? -eq 0 ] && [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        # Set permissions
        if [ "$IS_ROOT" = true ]; then
            chmod 600 "$KEY_FILE"
            chmod 644 "$CERT_FILE"
            chown "$SERVICE_USER:$SERVICE_GROUP" "$CERT_FILE" "$KEY_FILE"
        else
            sudo chmod 600 "$KEY_FILE"
            sudo chmod 644 "$CERT_FILE"
            sudo chown "$SERVICE_USER:$SERVICE_GROUP" "$CERT_FILE" "$KEY_FILE"
        fi
        
        log_success "SSL certificate generated successfully"
        log_info "Certificate: $CERT_FILE"
        log_info "Private key: $KEY_FILE"
        EXPIRY=$(openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "$EXPIRY" ]; then
            log_info "Valid until: $EXPIRY"
        fi
    else
        log_warning "Failed to generate SSL certificate. Application will run without HTTPS."
        log_info "You can generate it later with: $INSTALL_DIR/generate-ssl-cert.sh"
    fi
}

# ============================================================================
# SETUP CERTIFICATE RENEWAL
# ============================================================================

setup_certificate_renewal() {
    log_step "Setting up automatic SSL certificate renewal..."
    
    # Copy certificate generation script
    if [ -f "$SCRIPT_DIR/generate-ssl-cert.sh" ]; then
        cp "$SCRIPT_DIR/generate-ssl-cert.sh" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/generate-ssl-cert.sh"
        
        # Create systemd timer for certificate renewal (runs yearly)
        RENEWAL_TIMER_FILE="/etc/systemd/system/odysafe-cti-platform-cert-renewal.timer"
        RENEWAL_SERVICE_FILE="/etc/systemd/system/odysafe-cti-platform-cert-renewal.service"
        
        # Create service file
        cat > "$RENEWAL_SERVICE_FILE" << EOF
[Unit]
Description=Renew SSL certificate for Odysafe CTI Platform
After=network.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/generate-ssl-cert.sh
ExecStartPost=/bin/systemctl restart odysafe-cti-platform.service
EOF
        
        # Create timer file (runs once per year, 11 months after installation)
        cat > "$RENEWAL_TIMER_FILE" << EOF
[Unit]
Description=Renew SSL certificate for Odysafe CTI Platform (yearly)
Requires=odysafe-cti-platform-cert-renewal.service

[Timer]
# Run yearly, starting 11 months from now
OnCalendar=*-*-* 00:00:00
OnBootSec=11month
OnUnitActiveSec=1year
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
        
        if [ "$IS_ROOT" = true ]; then
            systemctl daemon-reload
            systemctl enable odysafe-cti-platform-cert-renewal.timer
            systemctl start odysafe-cti-platform-cert-renewal.timer
        else
            sudo systemctl daemon-reload
            sudo systemctl enable odysafe-cti-platform-cert-renewal.timer
            sudo systemctl start odysafe-cti-platform-cert-renewal.timer
        fi
        
        log_success "Automatic certificate renewal configured (yearly)"
    else
        log_warning "Certificate generation script not found. Automatic renewal not configured."
    fi
}

# ============================================================================
# CONFIGURE LOG ROTATION
# ============================================================================

configure_log_rotation() {
    log_step "Configuring log rotation..."
    
    JOURNALD_CONF_FILE="journald-cti-platform.conf"
    JOURNALD_CONF_DIR="/etc/systemd/journald.conf.d"
    
    # Create journald.conf.d directory if it doesn't exist
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$JOURNALD_CONF_DIR"
    else
        sudo mkdir -p "$JOURNALD_CONF_DIR"
    fi
    
    # Copy journald configuration file
    if [ -f "$SCRIPT_DIR/$JOURNALD_CONF_FILE" ]; then
        if [ "$IS_ROOT" = true ]; then
            cp "$SCRIPT_DIR/$JOURNALD_CONF_FILE" "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE"
            systemctl restart systemd-journald
        else
            sudo cp "$SCRIPT_DIR/$JOURNALD_CONF_FILE" "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE"
            sudo systemctl restart systemd-journald
        fi
        
        log_success "Log rotation configured (max 500MB total, 30 days retention, daily rotation)"
    else
        log_warning "Journald configuration file not found: $JOURNALD_CONF_FILE"
        log_info "Log rotation will use system defaults"
    fi
}

# ============================================================================
# INSTALL SYSTEMD SERVICE
# ============================================================================

install_service() {
    log_step "Installing systemd service..."
    
    # Copy service file
    if [ "$IS_ROOT" = true ]; then
        cp "$SCRIPT_DIR/$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE"
        systemctl daemon-reload
        systemctl enable "$SERVICE_FILE"
    else
        sudo cp "$SCRIPT_DIR/$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE"
        sudo systemctl daemon-reload
        sudo systemctl enable "$SERVICE_FILE"
    fi
    
    log_success "Systemd service installed and enabled"
}

# ============================================================================
# START SERVICE
# ============================================================================

start_service() {
    log_step "Starting Odysafe CTI Platform service..."
    
    if [ "$IS_ROOT" = true ]; then
        systemctl start "$SERVICE_FILE"
    else
        sudo systemctl start "$SERVICE_FILE"
    fi
    
    # Wait a moment for service to start
    sleep 2
    
    # Check service status
    if [ "$IS_ROOT" = true ]; then
        if systemctl is-active --quiet "$SERVICE_FILE"; then
            log_success "Odysafe CTI Platform service started successfully"
        else
            log_error "Service failed to start. Check status with: systemctl status $SERVICE_FILE"
            systemctl status "$SERVICE_FILE" || true
            exit 1
        fi
    else
        if sudo systemctl is-active --quiet "$SERVICE_FILE"; then
            log_success "Odysafe CTI Platform service started successfully"
        else
            log_error "Service failed to start. Check status with: sudo systemctl status $SERVICE_FILE"
            sudo systemctl status "$SERVICE_FILE" || true
            exit 1
        fi
    fi
}

# ============================================================================
# VERIFY INSTALLATION
# ============================================================================

verify_installation() {
    log_step "Verifying installation..."
    
    # Check Python imports
    # Change to txt2stix directory so includes/ is found correctly
    cd "$INSTALL_DIR/repos/txt2stix-main"
    if [ "$IS_ROOT" = true ]; then
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" << EOF
import sys
import os
errors = []
warnings = []

# Ensure we're in txt2stix directory for includes resolution
os.chdir("$INSTALL_DIR/repos/txt2stix-main")

try:
    import flask
    print("✓ Flask installed")
except ImportError:
    errors.append("Flask not installed")

try:
    import iocsearcher
    print("✓ iocsearcher installed")
except ImportError:
    errors.append("iocsearcher not installed")

try:
    # Import txt2stix from txt2stix directory (includes/ will be found)
    import txt2stix
    print("✓ txt2stix installed")
except ImportError as e:
    warnings.append(f"txt2stix import failed: {str(e)}")
except Exception as e:
    warnings.append(f"txt2stix error: {str(e)}")

if errors:
    print("\n❌ Errors detected:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

if warnings:
    print("\n⚠ Warnings (txt2stix may work at runtime):")
    for w in warnings:
        print(f"  - {w}")

print("\n✓ Installation verification successful")
EOF
    else
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" << EOF
import sys
import os
errors = []
warnings = []

# Ensure we're in txt2stix directory for includes resolution
os.chdir("$INSTALL_DIR/repos/txt2stix-main")

try:
    import flask
    print("✓ Flask installed")
except ImportError:
    errors.append("Flask not installed")

try:
    import iocsearcher
    print("✓ iocsearcher installed")
except ImportError:
    errors.append("iocsearcher not installed")

try:
    # Import txt2stix from txt2stix directory (includes/ will be found)
    import txt2stix
    print("✓ txt2stix installed")
except ImportError as e:
    warnings.append(f"txt2stix import failed: {str(e)}")
except Exception as e:
    warnings.append(f"txt2stix error: {str(e)}")

if errors:
    print("\n❌ Errors detected:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

if warnings:
    print("\n⚠ Warnings (txt2stix may work at runtime):")
    for w in warnings:
        print(f"  - {w}")

print("\n✓ Installation verification successful")
EOF
    fi

    if [ $? -eq 0 ]; then
        log_success "Installation verification successful"
    else
        log_error "Installation verification failed"
        exit 1
    fi
    
    # Return to install directory
    cd "$INSTALL_DIR"
}

# ============================================================================
# MAIN INSTALLATION FUNCTION
# ============================================================================

main() {
    show_logo
    
    log_info "=========================================="
    log_info "Odysafe CTI Platform Installation"
    log_info "=========================================="
    echo ""
    
    detect_environment
    
    if ! check_prerequisites; then
        display_missing
        install_prerequisites
    fi
    
    create_service_user
    install_files
    setup_python_environment
    create_directories
    generate_ssl_certificate
    setup_certificate_renewal
    download_deepdarkcti
    configure_log_rotation
    install_service
    start_service
    verify_installation
    
    echo ""
    log_success "=========================================="
    log_success "Installation completed successfully!"
    log_success "=========================================="
    echo ""
    log_info "Special thanks to all contributors and maintainers of the open-source"
    log_info "projects that make this platform possible. Your dedication and hard work"
    log_info "are greatly appreciated!"
    echo ""
    log_info "Odysafe CTI Platform is now running as a systemd service"
    log_info "Service name: $SERVICE_FILE"
    log_info "Installation directory: $INSTALL_DIR"
    echo ""
    log_info "Useful commands:"
    if [ "$IS_ROOT" = true ]; then
        echo "  - Check status:   systemctl status $SERVICE_FILE"
        echo "  - View logs:      journalctl -u $SERVICE_FILE -f"
        echo "  - Restart:        systemctl restart $SERVICE_FILE"
        echo "  - Stop:           systemctl stop $SERVICE_FILE"
    else
        echo "  - Check status:   sudo systemctl status $SERVICE_FILE"
        echo "  - View logs:      sudo journalctl -u $SERVICE_FILE -f"
        echo "  - Restart:        sudo systemctl restart $SERVICE_FILE"
        echo "  - Stop:           sudo systemctl stop $SERVICE_FILE"
    fi
    echo ""
    log_info "The application should be accessible at:"
    log_info "  - http://localhost:5001"
    log_info "  - http://<SERVER_IP>:5001"
    echo ""
}

# Run main function
main
