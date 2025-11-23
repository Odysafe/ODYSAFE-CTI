#!/bin/bash

# ============================================================================
# Odysafe CTI Platform Installation Script
# Complete installation script for Odysafe CTI Platform as a systemd service
# ============================================================================

# Note: We use set -e selectively. Some functions need to handle errors themselves.
# We'll disable it temporarily in functions that need error handling.
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
# ROBUST EXECUTION FUNCTIONS
# ============================================================================

execute_with_retry() {
    # Execute a command with retry logic and multiple fallback methods
    # Usage: execute_with_retry "command" [max_attempts] [retry_delay] [use_sudo]
    local command="$1"
    local max_attempts="${2:-3}"
    local retry_delay="${3:-2}"
    local use_sudo="${4:-false}"
    local attempt=1
    local output=""
    local exit_code=1
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            log_info "Retrying command (attempt $attempt/$max_attempts)..."
            sleep $retry_delay
        fi
        
        # Try with or without sudo based on parameter
        if [ "$use_sudo" = "true" ] && [ "$IS_ROOT" = false ]; then
            output=$(eval "sudo $command" 2>&1)
            exit_code=$?
        else
            output=$(eval "$command" 2>&1)
            exit_code=$?
        fi
        
        if [ $exit_code -eq 0 ]; then
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    # If all attempts failed, log error and return failure
    log_error "Command failed after $max_attempts attempts: $command"
    echo "$output" | while IFS= read -r line; do
        log_error "$line"
    done
    return $exit_code
}

execute_with_fallback() {
    # Execute a command with multiple fallback methods
    # Usage: execute_with_fallback "method1" "method2" "method3" ...
    local methods=("$@")
    local output=""
    local exit_code=1
    
    for method in "${methods[@]}"; do
        log_info "Trying: $method"
        output=$(eval "$method" 2>&1)
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            return 0
        else
            log_warning "Method failed: $method"
            echo "$output" | while IFS= read -r line; do
                log_warning "$line"
            done
        fi
    done
    
    log_error "All methods failed"
    return 1
}

check_venv_prerequisites() {
    # Check prerequisites before creating virtual environment
    local python_cmd="$1"
    local target_dir="$2"
    local issues=0
    
    log_info "Checking prerequisites for virtual environment creation..."
    
    # Check if Python can import venv module
    if ! $python_cmd -c "import venv" 2>/dev/null; then
        log_warning "Python venv module not available, will need to install python3-venv"
        issues=$((issues + 1))
    else
        log_info "Python venv module: available"
    fi
    
    # Check if directory is writable
    if [ ! -w "$target_dir" ]; then
        log_warning "Directory $target_dir is not writable"
        issues=$((issues + 1))
    else
        log_info "Directory permissions: OK"
    fi
    
    # Check disk space (at least 500MB free)
    local available_space=$(df -m "$target_dir" | awk 'NR==2 {print $4}')
    if [ -n "$available_space" ] && [ "$available_space" -lt 500 ]; then
        log_warning "Low disk space: ${available_space}MB available (recommended: 500MB+)"
        issues=$((issues + 1))
    else
        log_info "Disk space: OK (${available_space}MB available)"
    fi
    
    # Check if Python is in PATH and executable
    if ! command -v "$python_cmd" &> /dev/null; then
        log_error "Python command not found: $python_cmd"
        return 1
    fi
    
    if [ $issues -eq 0 ]; then
        log_success "All prerequisites checked"
        return 0
    else
        log_warning "Some prerequisites need attention, but continuing..."
        return 0
    fi
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
    
    # Detect distribution with comprehensive support
    DISTRO=""
    DISTRO_VERSION=""
    DISTRO_VERSION_MINOR=""
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        
        # Extract major and minor version numbers
        if [ -n "$VERSION_ID" ]; then
            DISTRO_VERSION_MINOR=$(echo "$VERSION_ID" | cut -d'.' -f1,2)
        fi
        
        # Handle special cases
        if [ "$ID" = "rhel" ] || [ "$ID" = "centos" ] || [ "$ID" = "rocky" ] || [ "$ID" = "almalinux" ]; then
            if [ -f /etc/redhat-release ]; then
                # Extract version from redhat-release for better accuracy
                DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1 || echo "$VERSION_ID")
            fi
        fi
        
        log_info "Distribution detected: $DISTRO (version: ${DISTRO_VERSION:-unknown})"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        DISTRO_VERSION_MINOR=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
        log_info "Distribution detected: Debian (version: $DISTRO_VERSION)"
    elif [ -f /etc/redhat-release ]; then
        # Parse redhat-release file
        if grep -qi "centos" /etc/redhat-release; then
            DISTRO="centos"
        elif grep -qi "rocky" /etc/redhat-release; then
            DISTRO="rocky"
        elif grep -qi "almalinux" /etc/redhat-release; then
            DISTRO="almalinux"
        else
        DISTRO="rhel"
        fi
        DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1 || grep -oE '[0-9]+' /etc/redhat-release | head -1)
        DISTRO_VERSION_MINOR=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
        log_info "Distribution detected: $DISTRO (version: $DISTRO_VERSION)"
    elif [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
        DISTRO_VERSION=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
        log_info "Distribution detected: Fedora (version: $DISTRO_VERSION)"
    elif [ -f /etc/amazon-linux-release ]; then
        DISTRO="amzn"
        DISTRO_VERSION=$(grep -oE '[0-9]+' /etc/amazon-linux-release | head -1)
        log_info "Distribution detected: Amazon Linux (version: $DISTRO_VERSION)"
    else
        DISTRO="unknown"
        log_warning "Could not detect distribution, assuming Debian/Ubuntu"
    fi
    
    # Detect package manager based on distribution
    PKG_MANAGER=""
    if [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
        log_info "Package manager: apt"
    elif command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        log_info "Package manager: apt-get"
        else
            log_error "No supported package manager found (apt, apt-get)"
            exit 1
        fi
    elif [[ "$DISTRO" == "rhel" || "$DISTRO" == "centos" || "$DISTRO" == "rocky" || "$DISTRO" == "almalinux" || "$DISTRO" == "fedora" || "$DISTRO" == "amzn" ]]; then
        if command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        log_info "Package manager: dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        log_info "Package manager: yum"
        else
            log_error "No supported package manager found (dnf, yum)"
            exit 1
        fi
    else
        # Generic detection for unknown distributions
        if command -v apt &> /dev/null; then
            PKG_MANAGER="apt"
            log_info "Package manager: apt (auto-detected)"
        elif command -v apt-get &> /dev/null; then
            PKG_MANAGER="apt-get"
            log_info "Package manager: apt-get (auto-detected)"
        elif command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
            log_info "Package manager: dnf (auto-detected)"
        elif command -v yum &> /dev/null; then
            PKG_MANAGER="yum"
            log_info "Package manager: yum (auto-detected)"
    else
        log_error "No supported package manager found (apt, apt-get, dnf, yum)"
        exit 1
        fi
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
            rhel|centos|rocky|almalinux|fedora|amzn)
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
            rhel|centos|rocky|almalinux|fedora|amzn)
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
    
    # Check wget or curl (needed for pip installation fallback)
    if ! command -v wget &> /dev/null && ! command -v curl &> /dev/null; then
        log_warning "Neither wget nor curl found. Some features may not work."
        case "$DISTRO" in
            debian|ubuntu)
                MISSING_PACKAGES+=("curl")
                ;;
            rhel|centos|rocky|almalinux|fedora|amzn)
                MISSING_PACKAGES+=("curl")
                ;;
        esac
    else
        if command -v curl &> /dev/null; then
            log_info "curl: available"
        elif command -v wget &> /dev/null; then
            log_info "wget: available"
        fi
    fi
    
    # Check getent (usually available but verify)
    if ! command -v getent &> /dev/null; then
        log_warning "getent not found. Group checking may fail."
        case "$DISTRO" in
            debian|ubuntu)
                MISSING_PACKAGES+=("libc-bin")
                ;;
        esac
    else
        log_info "getent: available"
    fi
    
    # Check python3-venv (distribution-specific)
    if [ -n "$PYTHON_CMD" ]; then
        # Try to import venv module first (fastest check)
        if $PYTHON_CMD -c "import venv" 2>/dev/null; then
        # Try to create a test venv to check if ensurepip is available
        TEST_VENV_DIR="/tmp/test_venv_$$"
        if $PYTHON_CMD -m venv "$TEST_VENV_DIR" &> /dev/null; then
            rm -rf "$TEST_VENV_DIR"
            log_info "python3-venv: available"
            else
                MISSING_COMMANDS+=("python3-venv")
                log_info "python3-venv module exists but venv creation failed, will need package"
            fi
        else
            MISSING_COMMANDS+=("python3-venv")
            case "$DISTRO" in
                debian|ubuntu)
                    # Get Python version (e.g., 3.11) and check for version-specific package
                    PYTHON_VERSION_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)
                    PYTHON_VENV_PKG="python${PYTHON_VERSION_MINOR}-venv"
                    # Check if version-specific package is installed
                    if ! dpkg -l 2>/dev/null | grep -q "^ii.*${PYTHON_VENV_PKG}"; then
                        MISSING_PACKAGES+=("$PYTHON_VENV_PKG")
                        log_info "Need version-specific package: $PYTHON_VENV_PKG"
                    fi
                    # Also check generic python3-venv as fallback
                    if ! dpkg -l 2>/dev/null | grep -q "^ii.*python3-venv"; then
                        if [[ ! " ${MISSING_PACKAGES[@]} " =~ " ${PYTHON_VENV_PKG} " ]]; then
                            MISSING_PACKAGES+=("python3-venv")
                        fi
                    fi
                    ;;
                rhel|centos|rocky|almalinux|fedora|amzn)
                    # For RHEL-based systems, check if python3-devel is installed
                    if [ "$PKG_MANAGER" = "yum" ]; then
                        if ! rpm -q python3-devel &>/dev/null; then
                    MISSING_PACKAGES+=("python3-devel")
                        fi
                    elif [ "$PKG_MANAGER" = "dnf" ]; then
                        if ! rpm -q python3-devel &>/dev/null; then
                            MISSING_PACKAGES+=("python3-devel")
                        fi
                    fi
                    ;;
                *)
                    # Generic fallback for unknown distributions
                    log_warning "Unknown distribution, cannot determine python3-venv package name"
                    ;;
            esac
        fi
    fi
    
    # Check build tools (for compiling Python packages)
    case "$DISTRO" in
        debian|ubuntu)
            # Use dpkg-query for more reliable checking
            if command -v dpkg-query &>/dev/null; then
                if ! dpkg-query -W -f='${Status}' build-essential 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("build-essential")
            fi
                if ! dpkg-query -W -f='${Status}' python3-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("python3-dev")
            fi
            # Check libmagic (required for python-magic)
                if ! dpkg-query -W -f='${Status}' libmagic1 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("libmagic1")
            fi
                if ! dpkg-query -W -f='${Status}' libmagic-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("libmagic-dev")
            fi
            # Check libxml2 and libxslt (required for lxml)
                if ! dpkg-query -W -f='${Status}' libxml2-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("libxml2-dev")
            fi
                if ! dpkg-query -W -f='${Status}' libxslt1-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("libxslt1-dev")
            fi
            # Check libffi (required for some Python packages)
                if ! dpkg-query -W -f='${Status}' libffi-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("libffi-dev")
            fi
            # Check libssl (required for SSL support in Python)
                if ! dpkg-query -W -f='${Status}' libssl-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("libssl-dev")
            fi
            # Check zlib (required for compression)
                if ! dpkg-query -W -f='${Status}' zlib1g-dev 2>/dev/null | grep -q "install ok installed"; then
                MISSING_PACKAGES+=("zlib1g-dev")
                fi
            else
                # Fallback to dpkg -l if dpkg-query not available
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*build-essential"; then
                    MISSING_PACKAGES+=("build-essential")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*python3-dev"; then
                    MISSING_PACKAGES+=("python3-dev")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*libmagic1"; then
                    MISSING_PACKAGES+=("libmagic1")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*libmagic-dev"; then
                    MISSING_PACKAGES+=("libmagic-dev")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*libxml2-dev"; then
                    MISSING_PACKAGES+=("libxml2-dev")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*libxslt1-dev"; then
                    MISSING_PACKAGES+=("libxslt1-dev")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*libffi-dev"; then
                    MISSING_PACKAGES+=("libffi-dev")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*libssl-dev"; then
                    MISSING_PACKAGES+=("libssl-dev")
                fi
                if ! dpkg -l 2>/dev/null | grep -q "^ii.*zlib1g-dev"; then
                    MISSING_PACKAGES+=("zlib1g-dev")
                fi
            fi
            ;;
        rhel|centos|rocky|almalinux|fedora|amzn)
            # Use rpm -q for checking installed packages (more reliable than rpm -qa | grep)
            if command -v rpm &>/dev/null; then
                if ! rpm -q gcc &>/dev/null; then
                MISSING_PACKAGES+=("gcc")
            fi
                if ! rpm -q python3-devel &>/dev/null; then
                MISSING_PACKAGES+=("python3-devel")
            fi
            # Check file-devel (required for python-magic)
                if ! rpm -q file-devel &>/dev/null; then
                MISSING_PACKAGES+=("file-devel")
            fi
            # Check libxml2 and libxslt (required for lxml)
                if ! rpm -q libxml2-devel &>/dev/null; then
                MISSING_PACKAGES+=("libxml2-devel")
            fi
                if ! rpm -q libxslt-devel &>/dev/null; then
                MISSING_PACKAGES+=("libxslt-devel")
            fi
            # Check libffi (required for some Python packages)
                if ! rpm -q libffi-devel &>/dev/null; then
                MISSING_PACKAGES+=("libffi-devel")
            fi
            # Check openssl-devel (required for SSL support in Python)
                if ! rpm -q openssl-devel &>/dev/null; then
                MISSING_PACKAGES+=("openssl-devel")
            fi
            # Check zlib-devel (required for compression)
                if ! rpm -q zlib-devel &>/dev/null; then
                MISSING_PACKAGES+=("zlib-devel")
                fi
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
            rhel|centos|rocky|almalinux|fedora|amzn)
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
    
    # Update package list with retry
    if [ "$PKG_MANAGER" = "apt" ] || [ "$PKG_MANAGER" = "apt-get" ]; then
        log_info "Updating package list..."
        if ! execute_with_retry "$PKG_MANAGER update" 3 5 false; then
            log_warning "Package list update failed, but continuing with installation..."
        fi
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        # For RHEL-based, update is usually not needed but can help
        log_info "Checking package manager..."
    fi
    
    # Install packages with retry
    log_info "Installing packages: ${MISSING_PACKAGES[*]}"
    local install_attempt=1
    local max_install_attempts=3
    local install_success=false
    
    while [ $install_attempt -le $max_install_attempts ] && [ "$install_success" = false ]; do
        if [ $install_attempt -gt 1 ]; then
            log_info "Retrying package installation (attempt $install_attempt/$max_install_attempts)..."
            sleep 5
        fi
        
        if [ "$IS_ROOT" = true ]; then
            if $PKG_MANAGER install -y "${MISSING_PACKAGES[@]}" 2>&1; then
                install_success=true
            fi
        else
            if sudo $PKG_MANAGER install -y "${MISSING_PACKAGES[@]}" 2>&1; then
                install_success=true
            fi
        fi
        
        install_attempt=$((install_attempt + 1))
    done
    
    if [ "$install_success" = false ]; then
        log_error "Failed to install prerequisites after $max_install_attempts attempts"
        log_error "Please install manually: $INSTALL_CMD ${MISSING_PACKAGES[*]}"
        exit 1
    fi
    
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
        log_info "Creating service user: $SERVICE_USER"
        # Try multiple methods to create user
        local user_created=false
        
        # Method 1: Try with useradd
        if [ "$IS_ROOT" = true ]; then
            if useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER" 2>/dev/null; then
                user_created=true
            fi
        else
            if sudo useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER" 2>/dev/null; then
                user_created=true
            fi
        fi
        
        # Method 2: Try without -d option if Method 1 failed
        if [ "$user_created" = false ]; then
            log_warning "Failed to create user with home directory, trying without..."
            if [ "$IS_ROOT" = true ]; then
                if useradd -r -s /bin/false "$SERVICE_USER" 2>/dev/null; then
                    user_created=true
                fi
            else
                if sudo useradd -r -s /bin/false "$SERVICE_USER" 2>/dev/null; then
                    user_created=true
                fi
            fi
        fi
        
        if [ "$user_created" = true ]; then
        log_success "Service user created: $SERVICE_USER"
        else
            log_error "Failed to create service user: $SERVICE_USER"
            exit 1
        fi
    else
        log_info "Service user already exists: $SERVICE_USER"
    fi
    
    # Ensure service group exists (create if needed)
    if ! getent group "$SERVICE_GROUP" &>/dev/null; then
        log_info "Creating service group: $SERVICE_GROUP"
        if [ "$IS_ROOT" = true ]; then
            groupadd -r "$SERVICE_GROUP" 2>/dev/null || true
        else
            sudo groupadd -r "$SERVICE_GROUP" 2>/dev/null || true
        fi
    fi
}

# ============================================================================
# INSTALL APPLICATION FILES
# ============================================================================

install_files() {
    log_step "Installing application files to $INSTALL_DIR..."
    
    # Create installation directory with fallback
    if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        if [ "$IS_ROOT" = false ]; then
            if ! sudo mkdir -p "$INSTALL_DIR" 2>/dev/null; then
                log_error "Failed to create installation directory: $INSTALL_DIR"
                exit 1
            fi
        else
            log_error "Failed to create installation directory: $INSTALL_DIR"
            exit 1
        fi
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
        if [ -d "$INSTALL_DIR/dependencies/repos" ]; then
            rm -rf "$INSTALL_DIR/dependencies/repos"
        fi
        if [ -f "$INSTALL_DIR/requirements.txt" ]; then
            rm -f "$INSTALL_DIR/requirements.txt"
        fi
    fi
    
    # Copy new files with error handling
    log_info "Copying application files..."
    if ! cp -r "$SCRIPT_DIR/cti-platform" "$INSTALL_DIR/" 2>/dev/null; then
        if [ "$IS_ROOT" = false ]; then
            if ! sudo cp -r "$SCRIPT_DIR/cti-platform" "$INSTALL_DIR/" 2>/dev/null; then
                log_error "Failed to copy cti-platform directory"
                exit 1
            fi
        else
            log_error "Failed to copy cti-platform directory"
            exit 1
        fi
    fi
    
    # Create dependencies directory if it doesn't exist
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$INSTALL_DIR/dependencies" 2>/dev/null || {
            log_error "Failed to create dependencies directory"
            exit 1
        }
    else
        sudo mkdir -p "$INSTALL_DIR/dependencies" 2>/dev/null || {
            log_error "Failed to create dependencies directory"
            exit 1
        }
    fi
    
    if ! cp -r "$SCRIPT_DIR/dependencies/repos" "$INSTALL_DIR/dependencies/" 2>/dev/null; then
        if [ "$IS_ROOT" = false ]; then
            if ! sudo cp -r "$SCRIPT_DIR/dependencies/repos" "$INSTALL_DIR/dependencies/" 2>/dev/null; then
                log_error "Failed to copy repos directory"
                exit 1
            fi
        else
            log_error "Failed to copy repos directory"
            exit 1
        fi
    fi
    
    if ! cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/" 2>/dev/null; then
        if [ "$IS_ROOT" = false ]; then
            if ! sudo cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/" 2>/dev/null; then
                log_error "Failed to copy requirements.txt"
                exit 1
            fi
        else
            log_error "Failed to copy requirements.txt"
            exit 1
        fi
    fi
    
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
    
    # Set ownership with error handling
    log_info "Setting file ownership..."
    if [ "$IS_ROOT" = true ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" 2>/dev/null || {
            log_warning "Failed to set ownership, but continuing..."
        }
    else
        sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" 2>/dev/null || {
            log_warning "Failed to set ownership, but continuing..."
        }
    fi
    
    log_success "Application files installed"
}

# ============================================================================
# PYTHON ENVIRONMENT SETUP
# ============================================================================

create_venv_robust() {
    # Create virtual environment with multiple fallback methods
    local venv_path="$1"
    local python_cmd="$2"
    local service_user="$3"
    local venv_dir=$(dirname "$venv_path")
    local venv_name=$(basename "$venv_path")
    local output=""
    local exit_code=1
    
    log_info "Creating virtual environment with robust fallback methods..."
    
    # Method 1: Try as service user
    log_info "Method 1: Creating venv as service user..."
    if id "$service_user" &>/dev/null; then
        # Use su if root, sudo -u if not root
            if [ "$IS_ROOT" = true ]; then
            output=$(su -s /bin/bash -c "\"$python_cmd\" -m venv \"$venv_path\"" "$service_user" 2>&1)
        else
            output=$(sudo -u "$service_user" "$python_cmd" -m venv "$venv_path" 2>&1)
        fi
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            log_success "Virtual environment created (Method 1: service user)"
            return 0
        else
            log_warning "Method 1 failed"
            if echo "$output" | grep -q "ensurepip is not available"; then
                log_info "ensurepip not available, will try other methods"
                    fi
                fi
            else
        log_warning "Service user $service_user does not exist, skipping Method 1"
    fi
    
    # Method 2: Try as current user (if root or if directory is accessible)
    log_info "Method 2: Creating venv as current user..."
    output=$("$python_cmd" -m venv "$venv_path" 2>&1)
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        log_success "Virtual environment created (Method 2: current user)"
        # Fix ownership if needed
        if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
            chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
        elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
            sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
        fi
        return 0
    else
        log_warning "Method 2 failed"
        if echo "$output" | grep -q "ensurepip is not available"; then
            log_info "ensurepip not available, trying to install python3-venv..."
        fi
    fi
    
    # Method 3: Install python3-venv and retry
    log_info "Method 3: Installing python3-venv package and retrying..."
    if install_python_venv_package "$python_cmd"; then
        # Retry Method 2 after installing package
        output=$("$python_cmd" -m venv "$venv_path" 2>&1)
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            log_success "Virtual environment created (Method 3: after installing python3-venv)"
            # Fix ownership if needed
            if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
            elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
            fi
            return 0
        fi
    fi
    
    # Method 4: Try with --without-pip and install pip manually
    log_info "Method 4: Creating venv without pip, will install pip manually..."
    output=$("$python_cmd" -m venv --without-pip "$venv_path" 2>&1)
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        log_info "Venv created without pip, installing pip manually..."
        # Activate venv and install pip
        if [ -f "$venv_path/bin/activate" ]; then
            # Try using ensurepip module first (Python 3.4+, usually available)
            if "$venv_path/bin/python" -m ensurepip --upgrade 2>/dev/null; then
                log_success "Virtual environment created (Method 4: without-pip + ensurepip)"
                # Fix ownership if needed
                if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                    chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                    sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                fi
                return 0
            fi
            
            # Try to install pip using get-pip.py if curl or wget is available
            # First check network connectivity
            NETWORK_AVAILABLE=false
            if command -v curl &>/dev/null; then
                if curl -sS --max-time 5 --connect-timeout 3 https://www.python.org &>/dev/null; then
                    NETWORK_AVAILABLE=true
                fi
            elif command -v wget &>/dev/null; then
                if wget -q --spider --timeout=5 --tries=1 https://www.python.org &>/dev/null; then
                    NETWORK_AVAILABLE=true
                fi
            fi
            
            if [ "$NETWORK_AVAILABLE" = true ]; then
                if command -v curl &>/dev/null; then
                    if curl -sS --max-time 30 --connect-timeout 10 https://bootstrap.pypa.io/get-pip.py 2>/dev/null | "$venv_path/bin/python" - 2>/dev/null; then
                        log_success "Virtual environment created (Method 4: without-pip + manual pip via curl)"
                        # Fix ownership if needed
                        if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                            chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                        elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                            sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                        fi
                        return 0
                    fi
                elif command -v wget &>/dev/null; then
                    if wget -qO- --timeout=30 --tries=2 https://bootstrap.pypa.io/get-pip.py 2>/dev/null | "$venv_path/bin/python" - 2>/dev/null; then
                        log_success "Virtual environment created (Method 4: without-pip + manual pip via wget)"
                        # Fix ownership if needed
                        if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                            chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                        elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                            sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                        fi
                        return 0
                    fi
                fi
            else
                log_warning "Network connectivity check failed. Skipping pip download from internet."
            fi
            
            log_warning "Failed to install pip manually (ensurepip, curl, and wget all failed)"
        else
            log_warning "Venv created but activation script not found"
        fi
    fi
    
    # All methods failed
    log_error "Failed to create virtual environment with all methods"
    echo "$output" | while IFS= read -r line; do
            log_error "$line"
        done
    return 1
}

install_python_venv_package() {
    # Install python3-venv package with distribution-specific logic
    local python_cmd="$1"
    local python_version=$($python_cmd --version 2>&1 | cut -d' ' -f2)
    local python_version_minor=$(echo "$python_version" | cut -d. -f1,2)
    local installed=false
    local output=""
    local exit_code=1
    
    log_info "Installing python3-venv package for $DISTRO..."
    
            if [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
        # Try version-specific package first
        local venv_pkg="python${python_version_minor}-venv"
        log_info "Trying to install $venv_pkg..."
        
        # $INSTALL_CMD already contains "apt install -y" or "sudo apt install -y"
        # Execute directly without execute_with_retry to avoid eval issues
        local attempt=1
        while [ $attempt -le 2 ] && [ "$installed" = false ]; do
            if [ $attempt -gt 1 ]; then
                log_info "Retrying installation (attempt $attempt/2)..."
                sleep 3
            fi
            output=$(eval "$INSTALL_CMD $venv_pkg" 2>&1)
            exit_code=$?
            if [ $exit_code -eq 0 ]; then
                installed=true
            fi
            attempt=$((attempt + 1))
        done
        
        if [ "$installed" = false ]; then
            log_warning "Failed to install $venv_pkg, trying python3-venv..."
            attempt=1
            while [ $attempt -le 2 ] && [ "$installed" = false ]; do
                if [ $attempt -gt 1 ]; then
                    log_info "Retrying installation (attempt $attempt/2)..."
                    sleep 3
                fi
                output=$(eval "$INSTALL_CMD python3-venv" 2>&1)
                exit_code=$?
                if [ $exit_code -eq 0 ]; then
                    installed=true
                fi
                attempt=$((attempt + 1))
            done
        fi
    elif [[ "$DISTRO" == "rhel" || "$DISTRO" == "centos" || "$DISTRO" == "rocky" || "$DISTRO" == "almalinux" || "$DISTRO" == "fedora" ]]; then
        # For RHEL-based systems, python3-venv is usually part of python3 package
        # But we may need python3-devel
        log_info "Checking python3-devel package..."
        local attempt=1
        while [ $attempt -le 2 ] && [ "$installed" = false ]; do
            if [ $attempt -gt 1 ]; then
                log_info "Retrying installation (attempt $attempt/2)..."
                sleep 3
            fi
            output=$(eval "$INSTALL_CMD python3-devel" 2>&1)
            exit_code=$?
            if [ $exit_code -eq 0 ]; then
                installed=true
            fi
            attempt=$((attempt + 1))
        done
    elif [[ "$DISTRO" == "amzn" ]]; then
        # Amazon Linux
        log_info "Installing python3-devel for Amazon Linux..."
        local attempt=1
        while [ $attempt -le 2 ] && [ "$installed" = false ]; do
            if [ $attempt -gt 1 ]; then
                log_info "Retrying installation (attempt $attempt/2)..."
                sleep 3
            fi
            output=$(eval "$INSTALL_CMD python3-devel" 2>&1)
            exit_code=$?
            if [ $exit_code -eq 0 ]; then
                installed=true
            fi
            attempt=$((attempt + 1))
        done
    else
        # Generic fallback
        log_info "Trying generic python3-venv installation..."
        local attempt=1
        while [ $attempt -le 2 ] && [ "$installed" = false ]; do
            if [ $attempt -gt 1 ]; then
                log_info "Retrying installation (attempt $attempt/2)..."
                sleep 3
            fi
            output=$(eval "$INSTALL_CMD python3-venv" 2>&1)
            exit_code=$?
            if [ $exit_code -eq 0 ]; then
                installed=true
            fi
            attempt=$((attempt + 1))
        done
    fi
    
    if [ "$installed" = true ]; then
        # Verify installation by testing venv import
        if $python_cmd -c "import venv" 2>/dev/null; then
            log_success "python3-venv package installed and verified"
            return 0
        else
            log_warning "Package installed but venv module still not available"
            return 1
        fi
    else
        log_warning "Failed to install python3-venv package"
        return 1
    fi
}

setup_python_environment() {
    log_step "Setting up Python virtual environment..."
    
    cd "$INSTALL_DIR" || {
        log_error "Cannot change to installation directory: $INSTALL_DIR"
        exit 1
    }
    
    # Remove existing venv if present
    if [ -d "venv" ]; then
        log_info "Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Check prerequisites
    if ! check_venv_prerequisites "$PYTHON_CMD" "$INSTALL_DIR"; then
        log_warning "Some prerequisites checks failed, but continuing..."
    fi
    
    # Ensure python3-venv package is available (will be installed by create_venv_robust if needed)
    # Pre-check and install if possible to avoid issues
    if ! $PYTHON_CMD -c "import venv" 2>/dev/null; then
        log_info "Python venv module not available, attempting to install python3-venv package..."
        install_python_venv_package "$PYTHON_CMD" || log_warning "Could not install python3-venv, will try alternative methods"
    fi
    
    # Create virtual environment using robust method with fallbacks
    log_info "Creating virtual environment with $PYTHON_CMD..."
    if ! create_venv_robust "$INSTALL_DIR/venv" "$PYTHON_CMD" "$SERVICE_USER"; then
        log_error "Failed to create virtual environment with all available methods"
        log_error "Please ensure python3-venv package is installed for your distribution"
        exit 1
    fi
    
    # Verify venv was created successfully
    if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ]; then
        log_error "Virtual environment was not created correctly"
        exit 1
    fi
    
    # Activate virtual environment
    source venv/bin/activate || {
        log_error "Failed to activate virtual environment"
        exit 1
    }
    
    # Upgrade pip, setuptools, wheel with retry
    log_info "Upgrading pip, setuptools, wheel..."
    if ! execute_with_retry "$PIP_CMD install --upgrade pip setuptools wheel --quiet" 3 2 false; then
        log_warning "Failed to upgrade pip with retry, trying without --quiet for diagnostics..."
        $PIP_CMD install --upgrade pip setuptools wheel 2>&1 | head -20
        log_error "Failed to upgrade pip, setuptools, wheel"
        exit 1
    fi
    
    # Install main dependencies with retry
    log_info "Installing main dependencies from requirements.txt..."
    if ! execute_with_retry "$PIP_CMD install -r requirements.txt --quiet" 3 5 false; then
        log_warning "Failed to install dependencies with retry, trying without --quiet for diagnostics..."
        $PIP_CMD install -r requirements.txt 2>&1 | tail -30
        log_error "Failed to install main dependencies"
        exit 1
    fi
    
    # Configure iocsearcher from local repository (already included in package)
    if [ -d "dependencies/repos/iocsearcher-main" ]; then
        log_info "Configuring iocsearcher from local repository..."
        if ! execute_with_retry "$PIP_CMD install -e dependencies/repos/iocsearcher-main --quiet" 3 3 false; then
            log_warning "Failed to install iocsearcher with retry, trying without --quiet..."
            if ! execute_with_retry "$PIP_CMD install -e dependencies/repos/iocsearcher-main" 2 3 false; then
                log_error "Failed to install iocsearcher"
                exit 1
            fi
        fi
        log_success "iocsearcher configured"
    else
        log_error "iocsearcher repository not found in dependencies/repos/iocsearcher-main"
        log_error "The package is incomplete. Please ensure dependencies/repos/iocsearcher-main is present."
        exit 1
    fi
    
    # Configure txt2stix from local repository (already included in package)
    if [ -d "dependencies/repos/txt2stix-main" ]; then
        log_info "Configuring txt2stix from local repository..."
        
        # Install txt2stix dependencies first if requirements.txt exists
        if [ -f "dependencies/repos/txt2stix-main/requirements.txt" ]; then
            if ! execute_with_retry "$PIP_CMD install -r dependencies/repos/txt2stix-main/requirements.txt --quiet" 3 3 false; then
                log_warning "Failed to install txt2stix dependencies with retry, trying without --quiet..."
                execute_with_retry "$PIP_CMD install -r dependencies/repos/txt2stix-main/requirements.txt" 2 3 false || {
                    log_error "Failed to install txt2stix dependencies"
                    exit 1
                }
            fi
        fi
        
        # Install txt2stix from its directory (needed for includes path resolution)
        # Change to txt2stix directory so includes/ is found correctly
        TXT2STIX_DIR="$INSTALL_DIR/dependencies/repos/txt2stix-main"
        cd "$TXT2STIX_DIR" || {
            log_error "Cannot change to txt2stix directory: $TXT2STIX_DIR"
            exit 1
        }
        if ! execute_with_retry "$PIP_CMD install -e . --quiet" 3 3 false; then
            log_warning "Failed to install txt2stix with retry, trying without --quiet..."
            if ! execute_with_retry "$PIP_CMD install -e ." 2 3 false; then
                log_error "Failed to install txt2stix"
        cd "$INSTALL_DIR"
                exit 1
            fi
        fi
        cd "$INSTALL_DIR" || {
            log_error "Cannot return to installation directory"
            exit 1
        }
        log_success "txt2stix configured"
    else
        log_error "txt2stix repository not found in dependencies/repos/txt2stix-main"
        log_error "The package is incomplete. Please ensure dependencies/repos/txt2stix-main is present."
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
    
    cd "$INSTALL_DIR/cti-platform" || {
        log_error "Cannot change to cti-platform directory: $INSTALL_DIR/cti-platform"
        exit 1
    }
    
    # Create directories with error handling
    local dirs=("uploads" "outputs/iocs" "outputs/stix" "outputs/reports" "database" "modules/cache" "ssl")
    local dir_created=true
    
    for dir in "${dirs[@]}"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
            log_warning "Failed to create directory: $dir, trying with sudo..."
            if [ "$IS_ROOT" = false ]; then
                if ! sudo mkdir -p "$dir" 2>/dev/null; then
                    log_error "Failed to create directory: $dir"
                    dir_created=false
                fi
            else
                log_error "Failed to create directory: $dir"
                dir_created=false
            fi
        fi
    done
    
    if [ "$dir_created" = false ]; then
        log_error "Some directories could not be created"
        exit 1
    fi
    
    # Set ownership with error handling
    local ownership_dirs=("uploads" "outputs" "database" "modules/cache" "ssl")
    for dir in "${ownership_dirs[@]}"; do
        if [ -d "$dir" ]; then
    if [ "$IS_ROOT" = true ]; then
                chown -R "$SERVICE_USER:$SERVICE_GROUP" "$dir" 2>/dev/null || {
                    log_warning "Failed to set ownership for $dir"
                }
    else
                sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$dir" 2>/dev/null || {
                    log_warning "Failed to set ownership for $dir"
                }
    fi
        fi
    done
    
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
        # If root, use su instead of sudo -u
        if id "$SERVICE_USER" &>/dev/null; then
            if su -s /bin/bash -c "git clone \"$DEEPDARKCTI_REPO_URL\" \"$DEEPDARKCTI_DIR\"" "$SERVICE_USER" 2>/dev/null; then
            log_success "deepdarkCTI repository downloaded"
        else
            log_warning "Unable to download deepdarkCTI repository. It can be downloaded later via the web interface."
        fi
    else
            # Service user doesn't exist, download as root
            if git clone "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" 2>/dev/null; then
                log_success "deepdarkCTI repository downloaded"
            else
                log_warning "Unable to download deepdarkCTI repository. It can be downloaded later via the web interface."
            fi
        fi
    else
        # Not root, use sudo -u
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
            # Try GNU date first (Linux), then BSD date (macOS/FreeBSD), then fallback
            EXPIRY_EPOCH="0"
            if date -d "$EXPIRY_DATE" +%s &>/dev/null; then
                # GNU date (Linux)
                EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || echo "0")
            elif date -j -f "%b %d %H:%M:%S %Y %Z" "$EXPIRY_DATE" +%s &>/dev/null 2>/dev/null; then
                # BSD date (macOS/FreeBSD) - try with timezone
                EXPIRY_EPOCH=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$EXPIRY_DATE" +%s 2>/dev/null || echo "0")
            elif date -j -f "%b %d %H:%M:%S %Y" "$EXPIRY_DATE" +%s &>/dev/null 2>/dev/null; then
                # BSD date without timezone
                EXPIRY_EPOCH=$(date -j -f "%b %d %H:%M:%S %Y" "$EXPIRY_DATE" +%s 2>/dev/null || echo "0")
            fi
            
            CURRENT_EPOCH=$(date +%s 2>/dev/null || echo "0")
            if [ "$EXPIRY_EPOCH" != "0" ] && [ "$CURRENT_EPOCH" != "0" ]; then
            DAYS_UNTIL_EXPIRY=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))
            else
                # If date parsing failed, assume certificate needs renewal
                DAYS_UNTIL_EXPIRY=0
            fi
            
            if [ "$DAYS_UNTIL_EXPIRY" -gt 30 ]; then
                log_info "SSL certificate already exists and is valid for $DAYS_UNTIL_EXPIRY more days"
                log_info "Certificate expires on: $EXPIRY_DATE"
                return 0
            else
                log_info "SSL certificate expires soon ($DAYS_UNTIL_EXPIRY days). Regenerating..."
            fi
        fi
    fi
    
    # Get hostname or IP with multiple fallbacks
    HOSTNAME="localhost"
    if command -v hostname &>/dev/null; then
        # Try FQDN first, then short hostname
        HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
    fi
    
    IP_ADDRESS="127.0.0.1"
    # Try multiple methods to get IP address
    if command -v hostname &>/dev/null && hostname -I &>/dev/null; then
    IP_ADDRESS=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.0.1")
    elif command -v ip &>/dev/null; then
        # Use ip command as fallback
        IP_ADDRESS=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || ip addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1 || echo "127.0.0.1")
    elif [ -f /etc/hosts ]; then
        # Last resort: try to extract from /etc/hosts
        IP_ADDRESS=$(grep -v '^#' /etc/hosts | grep -v '^$' | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "127.0.0.1")
    fi
    
    log_info "Generating self-signed SSL certificate..."
    log_info "Hostname: $HOSTNAME"
    log_info "IP Address: $IP_ADDRESS"
    log_info "Valid for: 1 year (365 days)"
    
    # Check OpenSSL version for -addext support (requires OpenSSL 1.1.1+)
    OPENSSL_VERSION=$(openssl version 2>/dev/null | awk '{print $2}' || echo "0.0.0")
    OPENSSL_MAJOR=$(echo "$OPENSSL_VERSION" | cut -d. -f1)
    OPENSSL_MINOR=$(echo "$OPENSSL_VERSION" | cut -d. -f2)
    OPENSSL_PATCH=$(echo "$OPENSSL_VERSION" | cut -d. -f3)
    
    USE_ADDEXT=false
    if [ "$OPENSSL_MAJOR" -gt 1 ] || ([ "$OPENSSL_MAJOR" -eq 1 ] && [ "$OPENSSL_MINOR" -gt 1 ]) || ([ "$OPENSSL_MAJOR" -eq 1 ] && [ "$OPENSSL_MINOR" -eq 1 ] && [ "${OPENSSL_PATCH:-0}" -ge 1 ]); then
        USE_ADDEXT=true
        log_info "OpenSSL version $OPENSSL_VERSION supports -addext"
    else
        log_warning "OpenSSL version $OPENSSL_VERSION is old. Using alternative method for SAN."
    fi
    
    # Generate certificate with or without -addext based on OpenSSL version
    if [ "$USE_ADDEXT" = true ]; then
        # Modern OpenSSL with -addext support
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
    else
        # Older OpenSSL - create config file for SAN
        SSL_CONFIG="/tmp/openssl-san-config-$$.cnf"
        cat > "$SSL_CONFIG" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = FR
ST = France
L = Paris
O = Odysafe
OU = CTI Platform
CN = $HOSTNAME

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $HOSTNAME
DNS.2 = localhost
IP.1 = $IP_ADDRESS
IP.2 = 127.0.0.1
EOF
        
        if [ "$IS_ROOT" = true ]; then
            openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
                -days 365 -nodes \
                -config "$SSL_CONFIG" \
                -extensions v3_req \
                2>/dev/null
        else
            sudo openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
                -days 365 -nodes \
                -config "$SSL_CONFIG" \
                -extensions v3_req \
                2>/dev/null
        fi
        rm -f "$SSL_CONFIG" 2>/dev/null || true
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
            if ! systemctl daemon-reload 2>/dev/null; then
                log_warning "Failed to reload systemd daemon for certificate renewal timer"
            fi
            if ! systemctl enable odysafe-cti-platform-cert-renewal.timer 2>/dev/null; then
                log_warning "Failed to enable certificate renewal timer"
            fi
            if ! systemctl start odysafe-cti-platform-cert-renewal.timer 2>/dev/null; then
                log_warning "Failed to start certificate renewal timer"
            fi
        else
            if ! sudo systemctl daemon-reload 2>/dev/null; then
                log_warning "Failed to reload systemd daemon for certificate renewal timer"
            fi
            if ! sudo systemctl enable odysafe-cti-platform-cert-renewal.timer 2>/dev/null; then
                log_warning "Failed to enable certificate renewal timer"
            fi
            if ! sudo systemctl start odysafe-cti-platform-cert-renewal.timer 2>/dev/null; then
                log_warning "Failed to start certificate renewal timer"
            fi
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
            if ! cp "$SCRIPT_DIR/$JOURNALD_CONF_FILE" "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" 2>/dev/null; then
                log_warning "Failed to copy journald configuration file"
            elif ! systemctl restart systemd-journald 2>/dev/null; then
                log_warning "Failed to restart systemd-journald. Configuration may not be active."
            else
                log_success "Log rotation configured (max 500MB total, 30 days retention, daily rotation)"
            fi
        else
            if ! sudo cp "$SCRIPT_DIR/$JOURNALD_CONF_FILE" "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" 2>/dev/null; then
                log_warning "Failed to copy journald configuration file"
            elif ! sudo systemctl restart systemd-journald 2>/dev/null; then
                log_warning "Failed to restart systemd-journald. Configuration may not be active."
            else
        log_success "Log rotation configured (max 500MB total, 30 days retention, daily rotation)"
            fi
        fi
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
    
    # Check if service file exists
    if [ ! -f "$SCRIPT_DIR/$SERVICE_FILE" ]; then
        log_error "Service file not found: $SCRIPT_DIR/$SERVICE_FILE"
        log_error "Please ensure the service file is present in the script directory"
        exit 1
    fi
    
    # Copy service file with error handling
    if [ "$IS_ROOT" = true ]; then
        if ! cp "$SCRIPT_DIR/$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to copy service file to /etc/systemd/system/"
            exit 1
        fi
        if ! systemctl daemon-reload 2>/dev/null; then
            log_error "Failed to reload systemd daemon"
            exit 1
        fi
        if ! systemctl enable "$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to enable service: $SERVICE_FILE"
            exit 1
        fi
    else
        if ! sudo cp "$SCRIPT_DIR/$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to copy service file to /etc/systemd/system/"
            exit 1
        fi
        if ! sudo systemctl daemon-reload 2>/dev/null; then
            log_error "Failed to reload systemd daemon"
            exit 1
        fi
        if ! sudo systemctl enable "$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to enable service: $SERVICE_FILE"
            exit 1
        fi
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
    cd "$INSTALL_DIR/dependencies/repos/txt2stix-main" || {
        log_error "Cannot change to txt2stix directory: $INSTALL_DIR/dependencies/repos/txt2stix-main"
        exit 1
    }
    
    # Create a temporary Python script for verification
    VERIFY_SCRIPT="/tmp/verify_install_$$.py"
    cat > "$VERIFY_SCRIPT" << 'PYEOF'
import sys
import os
errors = []
warnings = []

# Ensure we're in txt2stix directory for includes resolution
os.chdir("INSTALL_DIR_PLACEHOLDER/dependencies/repos/txt2stix-main")

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
PYEOF
    
    # Replace placeholder with actual install directory
    sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" "$VERIFY_SCRIPT"
    
    # Execute verification script
    if [ "$IS_ROOT" = true ]; then
        # If root, run as service user
        if id "$SERVICE_USER" &>/dev/null; then
            if ! su -s /bin/bash -c "$INSTALL_DIR/venv/bin/python $VERIFY_SCRIPT" "$SERVICE_USER" 2>&1; then
                log_error "Installation verification failed"
                rm -f "$VERIFY_SCRIPT" 2>/dev/null || true
                cd "$INSTALL_DIR" || true
                exit 1
            fi
        else
            # Service user doesn't exist, run as root
            if ! "$INSTALL_DIR/venv/bin/python" "$VERIFY_SCRIPT" 2>&1; then
        log_error "Installation verification failed"
                rm -f "$VERIFY_SCRIPT" 2>/dev/null || true
                cd "$INSTALL_DIR" || true
        exit 1
            fi
        fi
    else
        # Not root, use sudo to run as service user
        if id "$SERVICE_USER" &>/dev/null; then
            if ! sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" "$VERIFY_SCRIPT" 2>&1; then
                log_error "Installation verification failed"
                rm -f "$VERIFY_SCRIPT" 2>/dev/null || true
                cd "$INSTALL_DIR" || true
                exit 1
            fi
        else
            # Service user doesn't exist, run with sudo
            if ! sudo "$INSTALL_DIR/venv/bin/python" "$VERIFY_SCRIPT" 2>&1; then
                log_error "Installation verification failed"
                rm -f "$VERIFY_SCRIPT" 2>/dev/null || true
                cd "$INSTALL_DIR" || true
                exit 1
            fi
        fi
    fi
    
    # Cleanup
    rm -f "$VERIFY_SCRIPT" 2>/dev/null || true
    
    log_success "Installation verification successful"
    
    # Return to install directory
    cd "$INSTALL_DIR" || true
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
    
    # SSL Certificate information
    SSL_DIR="$INSTALL_DIR/cti-platform/ssl"
    CERT_FILE="$SSL_DIR/cert.pem"
    KEY_FILE="$SSL_DIR/key.pem"
    
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo ""
        log_info "=========================================="
        log_info "SSL Certificate Information"
        log_info "=========================================="
        echo ""
        log_info "A self-signed SSL certificate has been generated for HTTPS access."
        log_info "Certificate location:"
        log_info "  - Certificate: $CERT_FILE"
        log_info "  - Private key:  $KEY_FILE"
        echo ""
        log_warning "This is a self-signed certificate. Browsers will show a security warning."
        log_warning "For production use, replace it with your own certificate."
        echo ""
        log_info "To replace with your own certificate:"
        log_info "  1. Copy your certificate file to: $CERT_FILE"
        log_info "  2. Copy your private key file to: $KEY_FILE"
        log_info "  3. Set correct permissions:"
        if [ "$IS_ROOT" = true ]; then
            echo "     chmod 600 $KEY_FILE"
            echo "     chmod 644 $CERT_FILE"
            echo "     chown $SERVICE_USER:$SERVICE_GROUP $CERT_FILE $KEY_FILE"
        else
            echo "     sudo chmod 600 $KEY_FILE"
            echo "     sudo chmod 644 $CERT_FILE"
            echo "     sudo chown $SERVICE_USER:$SERVICE_GROUP $CERT_FILE $KEY_FILE"
        fi
        if [ "$IS_ROOT" = true ]; then
            echo "  4. Restart the service: systemctl restart $SERVICE_FILE"
        else
            echo "  4. Restart the service: sudo systemctl restart $SERVICE_FILE"
        fi
        echo ""
    else
        log_warning "SSL certificate was not generated. HTTPS will not be available."
        log_info "You can generate it later with: $INSTALL_DIR/generate-ssl-cert.sh"
        echo ""
    fi
}

# Run main function
main

