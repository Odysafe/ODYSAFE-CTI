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

# Port configuration (will be set dynamically)
CTI_PORT=""

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
    echo -e "${YELLOW}[INFO]${NC} $1"
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
    # Execute a command with retry logic and exponential backoff
    # Usage: execute_with_retry "command" [max_attempts] [initial_retry_delay] [use_sudo]
    local command="$1"
    local max_attempts="${2:-3}"
    local initial_retry_delay="${3:-2}"
    local use_sudo="${4:-false}"
    local attempt=1
    local output=""
    local exit_code=1
    local retry_delay=$initial_retry_delay
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            log_info "Retrying command (attempt $attempt/$max_attempts, delay: ${retry_delay}s)..."
            sleep $retry_delay
            # Exponential backoff: double the delay each time
            retry_delay=$((retry_delay * 2))
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
        log_info "Python venv module not available, will be installed during setup"
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

detect_os_enhanced() {
    # Enhanced OS detection with multiple methods
    DISTRO=""
    DISTRO_VERSION=""
    DISTRO_VERSION_MINOR=""
    
    # Method 1: /etc/os-release (most reliable, POSIX standard)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        
        # Handle ID_LIKE for better compatibility
        if [ -n "$ID_LIKE" ]; then
            case "$ID_LIKE" in
                *debian*)
                    if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
                        log_info "Distribution $ID is Debian-like"
                    fi
                    ;;
                *rhel*|*fedora*)
                    if [ "$ID" != "rhel" ] && [ "$ID" != "centos" ] && [ "$ID" != "rocky" ] && [ "$ID" != "almalinux" ] && [ "$ID" != "fedora" ]; then
                        log_info "Distribution $ID is RHEL-like"
                    fi
                    ;;
            esac
        fi
        
        # Extract major and minor version numbers
        if [ -n "$VERSION_ID" ]; then
            DISTRO_VERSION_MINOR=$(echo "$VERSION_ID" | cut -d'.' -f1,2)
        fi
        
        # Handle special cases for RHEL-based
        if [ "$ID" = "rhel" ] || [ "$ID" = "centos" ] || [ "$ID" = "rocky" ] || [ "$ID" = "almalinux" ]; then
            if [ -f /etc/redhat-release ]; then
                # Extract version from redhat-release for better accuracy
                DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1 || echo "$VERSION_ID")
                DISTRO_VERSION_MINOR=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
            fi
        fi
        
        # Handle Ubuntu codenames (convert to version if needed)
        if [ "$ID" = "ubuntu" ] && [ -n "$VERSION_CODENAME" ]; then
            log_info "Ubuntu codename: $VERSION_CODENAME"
        fi
        
        log_info "Distribution detected (os-release): $DISTRO (version: ${DISTRO_VERSION:-unknown})"
        return 0
    fi
    
    # Method 2: lsb_release (if available)
    if command -v lsb_release &> /dev/null; then
        DISTRO=$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "")
        DISTRO_VERSION=$(lsb_release -sr 2>/dev/null || echo "")
        if [ -n "$DISTRO" ] && [ -n "$DISTRO_VERSION" ]; then
            DISTRO_VERSION_MINOR=$(echo "$DISTRO_VERSION" | cut -d'.' -f1,2)
            log_info "Distribution detected (lsb_release): $DISTRO (version: $DISTRO_VERSION)"
            return 0
        fi
    fi
    
    # Method 3: hostnamectl (systemd)
    if command -v hostnamectl &> /dev/null; then
        local hctl_os=$(hostnamectl 2>/dev/null | grep -i "operating system" | cut -d':' -f2 | sed 's/^[[:space:]]*//' | tr '[:upper:]' '[:lower:]' || echo "")
        if [ -n "$hctl_os" ]; then
            if echo "$hctl_os" | grep -qi "debian"; then
                DISTRO="debian"
            elif echo "$hctl_os" | grep -qi "ubuntu"; then
                DISTRO="ubuntu"
            elif echo "$hctl_os" | grep -qi "centos"; then
                DISTRO="centos"
            elif echo "$hctl_os" | grep -qi "rocky"; then
                DISTRO="rocky"
            elif echo "$hctl_os" | grep -qi "almalinux"; then
                DISTRO="almalinux"
            elif echo "$hctl_os" | grep -qi "fedora"; then
                DISTRO="fedora"
            fi
            if [ -n "$DISTRO" ]; then
                log_info "Distribution detected (hostnamectl): $DISTRO"
                # Try to get version from other methods
                if [ -z "$DISTRO_VERSION" ]; then
                    if [ -f /etc/debian_version ]; then
                        DISTRO_VERSION=$(cat /etc/debian_version)
                    elif [ -f /etc/redhat-release ]; then
                        DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1 || grep -oE '[0-9]+' /etc/redhat-release | head -1)
                    fi
                fi
                return 0
            fi
        fi
    fi
    
    # Method 4: /etc/debian_version
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        DISTRO_VERSION_MINOR=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
        log_info "Distribution detected (debian_version): Debian (version: $DISTRO_VERSION)"
        return 0
    fi
    
    # Method 5: /etc/redhat-release
    if [ -f /etc/redhat-release ]; then
        local rh_content=$(cat /etc/redhat-release)
        if echo "$rh_content" | grep -qi "centos"; then
            DISTRO="centos"
        elif echo "$rh_content" | grep -qi "rocky"; then
            DISTRO="rocky"
        elif echo "$rh_content" | grep -qi "almalinux"; then
            DISTRO="almalinux"
        elif echo "$rh_content" | grep -qi "fedora"; then
            DISTRO="fedora"
        else
            DISTRO="rhel"
        fi
        DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1 || grep -oE '[0-9]+' /etc/redhat-release | head -1)
        DISTRO_VERSION_MINOR=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
        log_info "Distribution detected (redhat-release): $DISTRO (version: $DISTRO_VERSION)"
        return 0
    fi
    
    # Method 6: /etc/fedora-release
    if [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
        DISTRO_VERSION=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
        log_info "Distribution detected (fedora-release): Fedora (version: $DISTRO_VERSION)"
        return 0
    fi
    
    # Method 7: /etc/amazon-linux-release
    if [ -f /etc/amazon-linux-release ]; then
        DISTRO="amzn"
        DISTRO_VERSION=$(grep -oE '[0-9]+' /etc/amazon-linux-release | head -1)
        log_info "Distribution detected (amazon-linux-release): Amazon Linux (version: $DISTRO_VERSION)"
        return 0
    fi
    
    # Fallback: unknown
    DISTRO="unknown"
    log_warning "Could not detect distribution with any method, assuming Debian/Ubuntu"
    return 1
}

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
    
    # Detect distribution with enhanced method
    if ! detect_os_enhanced; then
        log_warning "OS detection had issues, but continuing with best guess..."
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

detect_all_python_versions() {
    # Detect all available Python 3 versions and return them sorted by version
    local available_versions=()
    local py_cmd=""
    local version_str=""
    local major=0
    local minor=0
    
    # Check common Python 3 commands
    local python_commands=("python3.13" "python3.12" "python3.11" "python3.10" "python3.9" "python3.8" "python3.7" "python3.6" "python3")
    
    for py_cmd in "${python_commands[@]}"; do
        if command -v "$py_cmd" &> /dev/null; then
            version_str=$($py_cmd --version 2>&1 | cut -d' ' -f2)
            major=$(echo "$version_str" | cut -d'.' -f1)
            minor=$(echo "$version_str" | cut -d'.' -f2)
            
            # Only include Python 3.8+
            if [ "$major" -eq 3 ] && [ "$minor" -ge 8 ]; then
                available_versions+=("$py_cmd|$version_str|$major|$minor")
            fi
        fi
    done
    
    # Also check /usr/bin/python3* directly
    if [ -d /usr/bin ]; then
        for py_bin in /usr/bin/python3.*; do
            if [ -x "$py_bin" ] && [ -f "$py_bin" ]; then
                py_cmd=$(basename "$py_bin")
                if ! echo "${python_commands[@]}" | grep -q "$py_cmd"; then
                    version_str=$("$py_bin" --version 2>&1 | cut -d' ' -f2)
                    major=$(echo "$version_str" | cut -d'.' -f1)
                    minor=$(echo "$version_str" | cut -d'.' -f2)
                    if [ "$major" -eq 3 ] && [ "$minor" -ge 8 ]; then
                        available_versions+=("$py_bin|$version_str|$major|$minor")
                    fi
                fi
            fi
        done
    fi
    
    # Return versions (will be sorted by select_best_python)
    printf '%s\n' "${available_versions[@]}"
}

select_best_python() {
    # Select the best Python version from available versions
    # Prefers: highest version, then python3 over python3.X, then shortest path
    local best_cmd=""
    local best_version=""
    local best_major=0
    local best_minor=0
    local best_path=""
    
    while IFS='|' read -r py_cmd version_str major minor; do
        # Skip if version is too old
        if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 8 ]); then
            continue
        fi
        
        # Test if this Python actually works
        if ! $py_cmd -c "import sys; sys.exit(0)" 2>/dev/null; then
            continue
        fi
        
        # Prefer higher version
        if [ "$major" -gt "$best_major" ] || ([ "$major" -eq "$best_major" ] && [ "$minor" -gt "$best_minor" ]); then
            best_cmd="$py_cmd"
            best_version="$version_str"
            best_major="$major"
            best_minor="$minor"
            best_path="$py_cmd"
        elif [ "$major" -eq "$best_major" ] && [ "$minor" -eq "$best_minor" ]; then
            # Same version: prefer "python3" over "python3.X"
            if [ "$py_cmd" = "python3" ] && [ "$best_cmd" != "python3" ]; then
                best_cmd="$py_cmd"
                best_version="$version_str"
                best_path="$py_cmd"
            fi
        fi
    done < <(detect_all_python_versions | sort -t'|' -k3,3nr -k4,4nr)
    
    if [ -n "$best_cmd" ]; then
        PYTHON_CMD="$best_cmd"
        PYTHON_VERSION="$best_version"
        PYTHON_MAJOR="$best_major"
        PYTHON_MINOR="$best_minor"
        return 0
    fi
    
    return 1
}

detect_python() {
    log_step "Detecting Python installation..."
    
    # First try to select best Python from all available
    if select_best_python; then
        log_info "Python found: $PYTHON_CMD (version $PYTHON_VERSION)"
        
        # Verify pip compatibility
        if $PYTHON_CMD -m pip --version &> /dev/null; then
            log_success "Python $PYTHON_VERSION detected and compatible (pip available)"
            return 0
        else
            log_info "Python $PYTHON_VERSION detected but pip not available, will install pip"
            log_success "Python $PYTHON_VERSION detected and compatible"
            return 0
        fi
    fi
    
    # Fallback to original method if select_best_python failed
    log_warning "Advanced Python detection failed, trying fallback method..."
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

install_pip_robust() {
    # Install pip with multiple fallback methods
    # $1 = python command to use
    local python_cmd="${1:-$PYTHON_CMD}"
    local pip_installed=false
    
    if [ -z "$python_cmd" ]; then
        log_error "No Python command provided for pip installation"
        return 1
    fi
    
    log_info "Installing pip for $python_cmd..."
    
    # Method 1: Try ensurepip (built-in, Python 3.4+)
    if $python_cmd -m ensurepip --upgrade 2>/dev/null; then
        log_success "pip installed via ensurepip"
        pip_installed=true
    fi
    
    # Method 2: Try get-pip.py via curl
    if [ "$pip_installed" = false ] && command -v curl &>/dev/null; then
        log_info "Trying to install pip via get-pip.py (curl)..."
        if curl -sS --max-time 30 --connect-timeout 10 https://bootstrap.pypa.io/get-pip.py 2>/dev/null | $python_cmd 2>/dev/null; then
            log_success "pip installed via get-pip.py (curl)"
            pip_installed=true
        fi
    fi
    
    # Method 3: Try get-pip.py via wget
    if [ "$pip_installed" = false ] && command -v wget &>/dev/null; then
        log_info "Trying to install pip via get-pip.py (wget)..."
        if wget -qO- --timeout=30 --tries=2 https://bootstrap.pypa.io/get-pip.py 2>/dev/null | $python_cmd 2>/dev/null; then
            log_success "pip installed via get-pip.py (wget)"
            pip_installed=true
        fi
    fi
    
    # Method 4: Try installing python3-pip package
    if [ "$pip_installed" = false ]; then
        log_info "Trying to install pip via system package manager..."
        if [ "$PKG_MANAGER" = "apt" ] || [ "$PKG_MANAGER" = "apt-get" ]; then
            if execute_with_retry "$INSTALL_CMD python3-pip" 2 3 false; then
                pip_installed=true
            fi
        elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
            if execute_with_retry "$INSTALL_CMD python3-pip" 2 3 false; then
                pip_installed=true
            fi
        fi
    fi
    
    if [ "$pip_installed" = true ]; then
        # Verify pip is now available
        if $python_cmd -m pip --version &> /dev/null; then
            PIP_CMD="$python_cmd -m pip"
            log_success "pip verified and ready: $PIP_CMD"
            return 0
        fi
    fi
    
    log_error "Failed to install pip with all available methods"
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
        # Verify this pip3 works with our Python
        if [ -n "$PYTHON_CMD" ]; then
            if pip3 --version &> /dev/null && pip3 --python "$PYTHON_CMD" --version &> /dev/null 2>&1; then
                PIP_CMD="pip3"
                log_success "pip found: pip3 (compatible with $PYTHON_CMD)"
                return 0
            fi
        else
            PIP_CMD="pip3"
            log_success "pip found: pip3"
            return 0
        fi
    fi
    
    if command -v pip &> /dev/null; then
        # Verify this pip works with our Python
        if [ -n "$PYTHON_CMD" ]; then
            if pip --version &> /dev/null && pip --python "$PYTHON_CMD" --version &> /dev/null 2>&1; then
                PIP_CMD="pip"
                log_success "pip found: pip (compatible with $PYTHON_CMD)"
                return 0
            fi
        else
            PIP_CMD="pip"
            log_success "pip found: pip"
            return 0
        fi
    fi
    
    log_warning "pip not found, will attempt to install"
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
            # Use multiple methods to verify libmagic1 is installed
            libmagic1_installed=false
            if dpkg-query -W -f='${Status}' libmagic1 2>/dev/null | grep -q "install ok installed"; then
                libmagic1_installed=true
            elif dpkg -l 2>/dev/null | grep -q "^ii.*libmagic1"; then
                libmagic1_installed=true
            elif [ -f "/usr/lib/x86_64-linux-gnu/libmagic.so.1" ] || [ -f "/usr/lib/libmagic.so.1" ] || [ -f "/lib/x86_64-linux-gnu/libmagic.so.1" ]; then
                libmagic1_installed=true
            elif command -v file >/dev/null 2>&1 && file --version >/dev/null 2>&1; then
                # If file command works, libmagic1 is likely installed
                libmagic1_installed=true
            fi
            
            if [ "$libmagic1_installed" = false ]; then
                MISSING_PACKAGES+=("libmagic1")
            fi
            
            # Check libmagic-dev
            libmagic_dev_installed=false
            if dpkg-query -W -f='${Status}' libmagic-dev 2>/dev/null | grep -q "install ok installed"; then
                libmagic_dev_installed=true
            elif dpkg -l 2>/dev/null | grep -q "^ii.*libmagic-dev"; then
                libmagic_dev_installed=true
            fi
            
            if [ "$libmagic_dev_installed" = false ]; then
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
                # Check libmagic1 with multiple methods
                libmagic1_installed=false
                if dpkg -l 2>/dev/null | grep -q "^ii.*libmagic1"; then
                    libmagic1_installed=true
                elif [ -f "/usr/lib/x86_64-linux-gnu/libmagic.so.1" ] || [ -f "/usr/lib/libmagic.so.1" ] || [ -f "/lib/x86_64-linux-gnu/libmagic.so.1" ]; then
                    libmagic1_installed=true
                elif command -v file >/dev/null 2>&1 && file --version >/dev/null 2>&1; then
                    libmagic1_installed=true
                fi
                
                if [ "$libmagic1_installed" = false ]; then
                    MISSING_PACKAGES+=("libmagic1")
                fi
                
                # Check libmagic-dev
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

get_package_name_for_os() {
    # Get the correct package name for a given package and OS/version
    # $1 = generic package name
    # Returns: OS-specific package name(s) to try
    local generic_pkg="$1"
    local pkg_names=()
    
    case "$generic_pkg" in
        python3)
            pkg_names=("python3")
            ;;
        python3-pip)
            if [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
                pkg_names=("python3-pip" "python-pip3")
            elif [[ "$DISTRO" == "rhel" || "$DISTRO" == "centos" || "$DISTRO" == "rocky" || "$DISTRO" == "almalinux" ]]; then
                pkg_names=("python3-pip" "python3-pip3")
            elif [[ "$DISTRO" == "fedora" ]]; then
                pkg_names=("python3-pip")
            elif [[ "$DISTRO" == "amzn" ]]; then
                pkg_names=("python3-pip" "python3-pip3")
            else
                pkg_names=("python3-pip")
            fi
            ;;
        python3-venv|python3-dev|build-essential|libmagic1)
            # These are handled in check_prerequisites with OS-specific logic
            pkg_names=("$generic_pkg")
            ;;
        git)
            pkg_names=("git")
            ;;
        *)
            pkg_names=("$generic_pkg")
            ;;
    esac
    
    printf '%s\n' "${pkg_names[@]}"
}

install_system_package_robust() {
    # Install a system package with multiple fallback names
    # $1 = generic package name
    local generic_pkg="$1"
    local installed=false
    local pkg_name=""
    
    # Get OS-specific package names to try
    local pkg_names=()
    while IFS= read -r pkg_name; do
        pkg_names+=("$pkg_name")
    done < <(get_package_name_for_os "$generic_pkg")
    
    # Check if already installed
    for pkg_name in "${pkg_names[@]}"; do
        if [[ "$PKG_MANAGER" == "apt" || "$PKG_MANAGER" == "apt-get" ]]; then
            if dpkg -l 2>/dev/null | grep -q "^ii.*${pkg_name}"; then
                log_info "$generic_pkg is already installed (as $pkg_name)"
                return 0
            fi
        elif [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
            if rpm -q "$pkg_name" &>/dev/null; then
                log_info "$generic_pkg is already installed (as $pkg_name)"
                return 0
            fi
        fi
    done
    
    # Try to install with each package name
    for pkg_name in "${pkg_names[@]}"; do
        log_info "Attempting to install $generic_pkg as: $pkg_name"
        if execute_with_retry "$INSTALL_CMD $pkg_name" 2 3 false; then
            log_success "$generic_pkg installed successfully (as $pkg_name)"
            installed=true
            break
        else
            log_warning "Failed to install $pkg_name, trying next alternative..."
        fi
    done
    
    if [ "$installed" = false ]; then
        log_error "Failed to install $generic_pkg with all package name alternatives: ${pkg_names[*]}"
        return 1
    fi
    
    return 0
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
        # Try to enable EPEL if available (helps with some packages)
        if [ "$PKG_MANAGER" = "yum" ] && [ "$DISTRO" != "fedora" ]; then
            if ! rpm -q epel-release &>/dev/null; then
                log_info "EPEL repository not found, but continuing..."
            fi
        fi
    fi
    
    # Install packages one by one with robust method
    log_info "Installing packages: ${MISSING_PACKAGES[*]}"
    local failed_packages=()
    
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if ! install_system_package_robust "$pkg"; then
            failed_packages+=("$pkg")
            log_warning "Failed to install $pkg, but continuing with other packages..."
        fi
    done
    
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_error "Failed to install some prerequisites: ${failed_packages[*]}"
        log_error "Please install manually: $INSTALL_CMD ${failed_packages[*]}"
        # Don't exit immediately, continue to see if we can work without them
        log_warning "Continuing installation, but some features may not work..."
    fi
    
    # Re-detect Python and pip after installation
    if ! detect_python; then
        log_error "Python installation failed"
        exit 1
    fi
    
    if ! detect_pip; then
        log_info "pip not found, attempting to install..."
        if ! install_pip_robust "$PYTHON_CMD"; then
            log_error "pip installation failed"
            exit 1
        fi
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
    
    # Copy new files with error handling (use rsync if available for incremental copy)
    log_info "Copying application files..."
    if command -v rsync &>/dev/null; then
        # Use rsync for incremental copy (only changed files)
        log_info "Using rsync for efficient file copying..."
        if [ "$IS_ROOT" = true ]; then
            rsync -a --update --delete "$SCRIPT_DIR/cti-platform/" "$INSTALL_DIR/cti-platform/" 2>/dev/null || {
                log_error "Failed to copy cti-platform directory with rsync"
                exit 1
            }
        else
            sudo rsync -a --update --delete "$SCRIPT_DIR/cti-platform/" "$INSTALL_DIR/cti-platform/" 2>/dev/null || {
                log_error "Failed to copy cti-platform directory with rsync"
                exit 1
            }
        fi
    else
        # Fallback to cp if rsync not available
        if [ ! -d "$INSTALL_DIR/cti-platform" ] || [ "$PRESERVE_DATA" = true ]; then
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
        else
            log_info "cti-platform directory already exists, skipping copy"
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
    
    # Copy dependencies/repos (use rsync if available)
    if command -v rsync &>/dev/null; then
        if [ "$IS_ROOT" = true ]; then
            rsync -a --update "$SCRIPT_DIR/dependencies/repos/" "$INSTALL_DIR/dependencies/repos/" 2>/dev/null || {
                log_error "Failed to copy repos directory with rsync"
                exit 1
            }
        else
            sudo rsync -a --update "$SCRIPT_DIR/dependencies/repos/" "$INSTALL_DIR/dependencies/repos/" 2>/dev/null || {
                log_error "Failed to copy repos directory with rsync"
                exit 1
            }
        fi
    else
        if [ ! -d "$INSTALL_DIR/dependencies/repos" ] || [ "$PRESERVE_DATA" = true ]; then
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
        else
            log_info "dependencies/repos directory already exists, skipping copy"
        fi
    fi
    
    # Copy requirements.txt only if different or missing
    if [ ! -f "$INSTALL_DIR/requirements.txt" ] || ! cmp -s "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt" 2>/dev/null; then
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
    else
        log_info "requirements.txt is up to date, skipping copy"
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

check_venv_validity() {
    # Check if virtual environment exists and is valid
    local venv_path="$1"
    
    if [ ! -d "$venv_path" ] || [ ! -f "$venv_path/bin/python" ]; then
        return 1  # Venv doesn't exist
    fi
    
    # Check if Python works
    if ! "$venv_path/bin/python" --version &>/dev/null; then
        return 1  # Python doesn't work
    fi
    
    # Check essential packages
    if ! "$venv_path/bin/python" -c "import flask" 2>/dev/null; then
        return 1  # Flask not installed
    fi
    
    if ! "$venv_path/bin/python" -c "import iocsearcher" 2>/dev/null; then
        return 1  # iocsearcher not installed
    fi
    
    # Check txt2stix (optional but recommended)
    if ! "$venv_path/bin/python" -c "import txt2stix" 2>/dev/null; then
        log_info "txt2stix not found in venv, will be installed during setup"
    fi
    
    # Check pdfalyzer (optional)
    if ! "$venv_path/bin/python" -c "from pdfalyzer.pdfalyzer import Pdfalyzer" 2>/dev/null; then
        log_info "pdfalyzer not found in venv, will be installed during setup"
    fi
    
    return 0  # Venv is valid
}

check_packages_installed() {
    # Check if packages from requirements.txt are installed
    local venv_path="$1"
    local requirements_file="$2"
    
    if [ ! -f "$requirements_file" ]; then
        return 1
    fi
    
    if [ ! -f "$venv_path/bin/pip" ]; then
        return 1
    fi
    
    # Get list of installed packages
    local installed_packages=$("$venv_path/bin/pip" list --format=freeze 2>/dev/null | cut -d'=' -f1 | tr '[:upper:]' '[:lower:]')
    
    # Check if main packages from requirements.txt are installed
    local missing_packages=0
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # Extract package name (before ==, >=, <=, etc.)
        local pkg_name=$(echo "$line" | sed -E 's/[[:space:]]*([^<>=!]+).*/\1/' | tr '[:upper:]' '[:lower:]' | xargs)
        
        if [ -n "$pkg_name" ]; then
            if ! echo "$installed_packages" | grep -q "^${pkg_name}$"; then
                missing_packages=$((missing_packages + 1))
            fi
        fi
    done < "$requirements_file"
    
    if [ $missing_packages -eq 0 ]; then
        return 0  # All packages installed
    else
        return 1  # Some packages missing
    fi
}

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
    
    # Method 5: Try with virtualenv if available
    log_info "Method 5: Trying virtualenv package..."
    if command -v virtualenv &> /dev/null; then
        log_info "virtualenv command found, using it..."
        output=$(virtualenv -p "$python_cmd" "$venv_path" 2>&1)
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            log_success "Virtual environment created (Method 5: virtualenv)"
            # Fix ownership if needed
            if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
            elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
            fi
            return 0
        else
            log_warning "Method 5 (virtualenv) failed"
        fi
    else
        log_info "virtualenv not available, trying to install..."
        # Try to install virtualenv
        if [ "$PKG_MANAGER" = "apt" ] || [ "$PKG_MANAGER" = "apt-get" ]; then
            if execute_with_retry "$INSTALL_CMD virtualenv" 2 3 false; then
                if virtualenv -p "$python_cmd" "$venv_path" 2>/dev/null; then
                    log_success "Virtual environment created (Method 5: virtualenv after install)"
                    # Fix ownership if needed
                    if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                        chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                    elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                        sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                    fi
                    return 0
                fi
            fi
        elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
            if execute_with_retry "$INSTALL_CMD python3-virtualenv" 2 3 false; then
                if virtualenv -p "$python_cmd" "$venv_path" 2>/dev/null; then
                    log_success "Virtual environment created (Method 5: virtualenv after install)"
                    # Fix ownership if needed
                    if [ "$IS_ROOT" = true ] && id "$service_user" &>/dev/null; then
                        chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                    elif [ "$IS_ROOT" = false ] && id "$service_user" &>/dev/null; then
                        sudo chown -R "$service_user:$SERVICE_GROUP" "$venv_path" 2>/dev/null || true
                    fi
                    return 0
                fi
            fi
        fi
    fi
    
    # All methods failed
    log_error "Failed to create virtual environment with all methods"
    echo "$output" | while IFS= read -r line; do
            log_error "$line"
        done
    return 1
}

test_venv_after_creation() {
    # Test that venv was created correctly and is functional
    local venv_path="$1"
    local python_cmd="$2"
    local test_passed=true
    
    log_info "Testing virtual environment..."
    
    # Test 1: Check venv directory exists
    if [ ! -d "$venv_path" ]; then
        log_error "Venv directory does not exist: $venv_path"
        test_passed=false
    fi
    
    # Test 2: Check Python executable exists
    if [ ! -f "$venv_path/bin/python" ]; then
        log_error "Python executable not found in venv: $venv_path/bin/python"
        test_passed=false
    fi
    
    # Test 3: Test Python can run
    if ! "$venv_path/bin/python" --version &>/dev/null; then
        log_error "Python in venv cannot execute --version"
        test_passed=false
    fi
    
    # Test 4: Test pip exists and works
    if [ ! -f "$venv_path/bin/pip" ]; then
        log_warning "pip not found in venv, will need to install"
    elif ! "$venv_path/bin/pip" --version &>/dev/null; then
        log_warning "pip in venv cannot execute --version"
    else
        log_info "pip verified in venv"
    fi
    
    # Test 5: Test basic import
    if ! "$venv_path/bin/python" -c "import sys; sys.exit(0)" 2>/dev/null; then
        log_error "Python in venv cannot execute basic imports"
        test_passed=false
    fi
    
    if [ "$test_passed" = true ]; then
        log_success "Virtual environment tests passed"
        return 0
    else
        log_error "Virtual environment tests failed"
        return 1
    fi
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
    
    # Check if venv exists and is valid
    if [ -d "venv" ]; then
        log_info "Checking existing virtual environment..."
        if check_venv_validity "$INSTALL_DIR/venv"; then
            log_success "Existing virtual environment is valid"
            
            # Check if packages are up to date
            if check_packages_installed "$INSTALL_DIR/venv" "$INSTALL_DIR/requirements.txt"; then
                log_success "All required packages are installed"
                log_info "Skipping venv creation and package installation"
                
                # Still check and install optional packages if needed
                if ! "$INSTALL_DIR/venv/bin/python" -c "import txt2stix" 2>/dev/null; then
                    log_info "Installing txt2stix..."
                    install_txt2stix_optional "$INSTALL_DIR/venv/bin/pip"
                fi
                
                if ! "$INSTALL_DIR/venv/bin/python" -c "from pdfalyzer.pdfalyzer import Pdfalyzer" 2>/dev/null; then
                    log_info "Installing pdfalyzer..."
                    install_pdfalyzer_optional "$INSTALL_DIR/venv/bin/pip"
                fi
                
                # Set ownership
                if [ "$IS_ROOT" = true ]; then
                    chown -R "$SERVICE_USER:$SERVICE_GROUP" venv 2>/dev/null || true
                else
                    sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" venv 2>/dev/null || true
                fi
                
                log_success "Python environment setup complete (using existing venv)"
                return 0
            else
                log_info "Some packages are missing, will update venv"
            fi
        else
            log_info "Existing virtual environment is invalid, will recreate"
            rm -rf venv
        fi
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
    
    # Test venv after creation
    if ! test_venv_after_creation "$INSTALL_DIR/venv" "$PYTHON_CMD"; then
        log_error "Virtual environment validation failed"
        log_error "Attempting to clean up and retry..."
        rm -rf "$INSTALL_DIR/venv"
        if ! create_venv_robust "$INSTALL_DIR/venv" "$PYTHON_CMD" "$SERVICE_USER"; then
            log_error "Failed to recreate virtual environment after validation failure"
            exit 1
        fi
        if ! test_venv_after_creation "$INSTALL_DIR/venv" "$PYTHON_CMD"; then
            log_error "Virtual environment still fails validation after retry"
            exit 1
        fi
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
    
    # Install main dependencies with flexible method
    log_info "Installing main dependencies from requirements.txt..."
    install_requirements_flexible "$PIP_CMD" "requirements.txt" || {
        log_error "Failed to install main dependencies"
        exit 1
    }
    
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
        
        # Fix SyntaxWarnings in iocsearcher (invalid escape sequences)
        log_info "Fixing SyntaxWarnings in iocsearcher..."
        IOCSEARCHER_DIR="$INSTALL_DIR/dependencies/repos/iocsearcher-main"
        if [ -f "$IOCSEARCHER_DIR/fix_syntax_warnings.py" ]; then
            if $PYTHON_CMD "$IOCSEARCHER_DIR/fix_syntax_warnings.py" 2>/dev/null; then
                log_success "SyntaxWarnings fixes applied to iocsearcher"
            else
                log_warning "Failed to apply SyntaxWarnings fixes (non-critical)"
            fi
        else
            log_warning "fix_syntax_warnings.py not found, skipping SyntaxWarnings fixes"
        fi
    else
        log_error "iocsearcher repository not found in dependencies/repos/iocsearcher-main"
        log_error "The package is incomplete. Please ensure dependencies/repos/iocsearcher-main is present."
        exit 1
    fi
    
    # Configure txt2stix and pdfalyzer from local repository (already included in package)
    install_txt2stix_optional "$PIP_CMD" || {
        log_error "Failed to install txt2stix"
        exit 1
    }
    install_pdfalyzer_optional "$PIP_CMD" || {
        log_warning "pdfalyzer installation failed, PDF analysis features will not be available"
    }
    
    # Set ownership
    if [ "$IS_ROOT" = true ]; then
        chown -R "$SERVICE_USER:$SERVICE_GROUP" venv
    else
        sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" venv
    fi
    
    log_success "Python environment setup complete"
}

install_txt2stix_optional() {
    # Install txt2stix if not already installed
    # $1 = pip command to use (should be venv/bin/pip)
    local pip_cmd="${1:-$PIP_CMD}"
    
    if [ -d "$INSTALL_DIR/dependencies/repos/txt2stix-main" ]; then
        # Check if already installed
        if "$INSTALL_DIR/venv/bin/python" -c "import txt2stix" 2>/dev/null; then
            log_info "txt2stix already installed, skipping"
            return 0
        fi
        
        log_info "Configuring txt2stix from local repository..."
        
        # Install txt2stix dependencies first if requirements.txt exists
        if [ -f "$INSTALL_DIR/dependencies/repos/txt2stix-main/requirements.txt" ]; then
            local current_dir_before=$(pwd)
            cd "$INSTALL_DIR" || {
                log_error "Cannot change to installation directory"
                return 1
            }
            if ! execute_with_retry "$pip_cmd install -r dependencies/repos/txt2stix-main/requirements.txt --quiet" 3 3 false; then
                log_warning "Failed to install txt2stix dependencies with retry, trying without --quiet..."
                execute_with_retry "$pip_cmd install -r dependencies/repos/txt2stix-main/requirements.txt" 2 3 false || {
                    log_error "Failed to install txt2stix dependencies"
                    cd "$current_dir_before" || true
                    return 1
                }
            fi
            cd "$current_dir_before" || true
        fi
        
        # Install txt2stix from its directory (needed for includes path resolution)
        TXT2STIX_DIR="$INSTALL_DIR/dependencies/repos/txt2stix-main"
        local current_dir=$(pwd)
        cd "$TXT2STIX_DIR" || {
            log_error "Cannot change to txt2stix directory: $TXT2STIX_DIR"
            return 1
        }
        if ! execute_with_retry "$pip_cmd install -e . --quiet" 3 3 false; then
            log_warning "Failed to install txt2stix with retry, trying without --quiet..."
            if ! execute_with_retry "$pip_cmd install -e ." 2 3 false; then
                log_error "Failed to install txt2stix"
                cd "$current_dir"
                return 1
            fi
        fi
        cd "$current_dir" || true
        log_success "txt2stix configured"
    else
        log_warning "txt2stix repository not found in dependencies/repos/txt2stix-main"
        return 1
    fi
}

install_pdfalyzer_optional() {
    # Install pdfalyzer if not already installed
    # $1 = pip command to use (should be venv/bin/pip)
    local pip_cmd="${1:-$PIP_CMD}"
    
    if [ -d "$INSTALL_DIR/dependencies/repos/pdfalyzer-main" ]; then
        # Check if already installed
        if "$INSTALL_DIR/venv/bin/python" -c "from pdfalyzer.pdfalyzer import Pdfalyzer" 2>/dev/null; then
            log_info "pdfalyzer already installed, skipping"
            return 0
        fi
        
        log_info "Configuring pdfalyzer from local repository..."
        
        # Install pdfalyzer from its directory
        PDFALYZER_DIR="$INSTALL_DIR/dependencies/repos/pdfalyzer-main"
        local current_dir=$(pwd)
        cd "$PDFALYZER_DIR" || {
            log_error "Cannot change to pdfalyzer directory: $PDFALYZER_DIR"
            return 1
        }
        if ! execute_with_retry "$pip_cmd install -e . --quiet" 3 3 false; then
            log_warning "Failed to install pdfalyzer with retry, trying without --quiet..."
            if ! execute_with_retry "$pip_cmd install -e ." 2 3 false; then
                log_warning "Failed to install pdfalyzer"
                cd "$current_dir"
                return 1
            fi
        fi
        cd "$current_dir" || true
        log_success "pdfalyzer configured"
    else
        log_warning "pdfalyzer repository not found in dependencies/repos/pdfalyzer-main"
        log_warning "PDF analysis features will not be available."
        return 1
    fi
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
    
    # Create directories with error handling (only if they don't exist)
    local dirs=("uploads" "outputs/iocs" "outputs/stix" "outputs/reports" "outputs/pdf_analysis" "database" "modules/cache" "ssl")
    local dir_created=true
    local dirs_created=0
    local dirs_skipped=0
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            dirs_skipped=$((dirs_skipped + 1))
            continue
        fi
        
        if ! mkdir -p "$dir" 2>/dev/null; then
            log_warning "Failed to create directory: $dir, trying with sudo..."
            if [ "$IS_ROOT" = false ]; then
                if ! sudo mkdir -p "$dir" 2>/dev/null; then
                    log_error "Failed to create directory: $dir"
                    dir_created=false
                else
                    dirs_created=$((dirs_created + 1))
                fi
            else
                log_error "Failed to create directory: $dir"
                dir_created=false
            fi
        else
            dirs_created=$((dirs_created + 1))
        fi
    done
    
    if [ $dirs_skipped -gt 0 ]; then
        log_info "$dirs_skipped directories already exist, skipped"
    fi
    if [ $dirs_created -gt 0 ]; then
        log_info "$dirs_created directories created"
    fi
    
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
    log_step "Downloading DeepDarkCTI repository..."
    
    DEEPDARKCTI_REPO_URL="https://github.com/fastfire/deepdarkCTI.git"
    DEEPDARKCTI_DIR="$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main"
    
    # Skip if already exists
    if [ -d "$DEEPDARKCTI_DIR" ] && [ -d "$DEEPDARKCTI_DIR/.git" ]; then
        log_info "DeepDarkCTI repository already exists, skipping download"
        log_info "Use the web interface to update it if needed"
        return 0
    fi
    
    # Create parent directory
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$(dirname "$DEEPDARKCTI_DIR")" 2>/dev/null || true
    else
        sudo mkdir -p "$(dirname "$DEEPDARKCTI_DIR")" 2>/dev/null || true
    fi
    
    # Download as service user
    if [ "$IS_ROOT" = true ]; then
        # If root, use su instead of sudo -u
        if id "$SERVICE_USER" &>/dev/null; then
            if su -s /bin/bash -c "git clone \"$DEEPDARKCTI_REPO_URL\" \"$DEEPDARKCTI_DIR\"" "$SERVICE_USER" 2>/dev/null; then
                log_success "DeepDarkCTI repository downloaded"
            else
                log_info "DeepDarkCTI repository will be downloaded during installation or can be downloaded later via the web interface."
            fi
        else
            # Service user doesn't exist, download as root
            if git clone "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" 2>/dev/null; then
                log_success "DeepDarkCTI repository downloaded"
            else
                log_info "DeepDarkCTI repository will be downloaded during installation or can be downloaded later via the web interface."
            fi
        fi
    else
        # Not root, use sudo -u
        if sudo -u "$SERVICE_USER" git clone "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" 2>/dev/null; then
            log_success "DeepDarkCTI repository downloaded"
        else
            log_info "DeepDarkCTI repository will be downloaded during installation or can be downloaded later via the web interface."
        fi
    fi
    
    # Set ownership
    if [ -d "$DEEPDARKCTI_DIR" ]; then
        if [ "$IS_ROOT" = true ]; then
            chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DEEPDARKCTI_DIR" 2>/dev/null || true
        else
            sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DEEPDARKCTI_DIR" 2>/dev/null || true
        fi
    fi
}

# ============================================================================
# DOWNLOAD RANSOMWARE TOOL MATRIX
# ============================================================================

download_ransomware_matrix() {
    log_step "Downloading Ransomware Tool Matrix repository..."
    
    RTM_REPO_URL="https://github.com/BushidoUK/Ransomware-Tool-Matrix.git"
    RTM_DIR="$INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main"
    
    # Skip if already exists
    if [ -d "$RTM_DIR" ] && [ -d "$RTM_DIR/.git" ]; then
        log_info "Ransomware Tool Matrix repository already exists, skipping download"
        log_info "Use the web interface to update it if needed"
        return 0
    fi
    
    # Create parent directory
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$(dirname "$RTM_DIR")" 2>/dev/null || true
    else
        sudo mkdir -p "$(dirname "$RTM_DIR")" 2>/dev/null || true
    fi
    
    # Download as service user
    if [ "$IS_ROOT" = true ]; then
        # If root, use su instead of sudo -u
        if id "$SERVICE_USER" &>/dev/null; then
            if su -s /bin/bash -c "git clone \"$RTM_REPO_URL\" \"$RTM_DIR\"" "$SERVICE_USER" 2>/dev/null; then
                log_success "Ransomware Tool Matrix repository downloaded"
            else
                log_info "Ransomware Tool Matrix repository will be downloaded during installation or can be downloaded later via the web interface."
            fi
        else
            # Service user doesn't exist, download as root
            if git clone "$RTM_REPO_URL" "$RTM_DIR" 2>/dev/null; then
                log_success "Ransomware Tool Matrix repository downloaded"
            else
                log_info "Ransomware Tool Matrix repository will be downloaded during installation or can be downloaded later via the web interface."
            fi
        fi
    else
        # Not root, use sudo -u
        if sudo -u "$SERVICE_USER" git clone "$RTM_REPO_URL" "$RTM_DIR" 2>/dev/null; then
            log_success "Ransomware Tool Matrix repository downloaded"
        else
            log_info "Ransomware Tool Matrix repository will be downloaded during installation or can be downloaded later via the web interface."
        fi
    fi
    
    # Set ownership
    if [ -d "$RTM_DIR" ]; then
        if [ "$IS_ROOT" = true ]; then
            chown -R "$SERVICE_USER:$SERVICE_GROUP" "$RTM_DIR" 2>/dev/null || true
        else
            sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$RTM_DIR" 2>/dev/null || true
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
    
    # Remove old certificates to regenerate them
    log_info "Removing old certificates if they exist..."
    if [ -f "$CERT_FILE" ]; then
        if [ "$IS_ROOT" = true ]; then
            rm -f "$CERT_FILE" 2>/dev/null || true
        else
            sudo rm -f "$CERT_FILE" 2>/dev/null || true
        fi
    fi
    if [ -f "$KEY_FILE" ]; then
        if [ "$IS_ROOT" = true ]; then
            rm -f "$KEY_FILE" 2>/dev/null || true
        else
            sudo rm -f "$KEY_FILE" 2>/dev/null || true
        fi
    fi
    
    # Check if certificate already exists (should not after removal above)
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
    
    # Force port 5001 (no port checking)
    CTI_PORT=5001
    SELECTED_PORT=5001
    
    # Check if service file exists
    if [ ! -f "$SCRIPT_DIR/$SERVICE_FILE" ]; then
        log_error "Service file not found: $SCRIPT_DIR/$SERVICE_FILE"
        log_error "Please ensure the service file is present in the script directory"
        exit 1
    fi
    
    # Create service file with dynamic port
    log_info "Creating systemd service with port $SELECTED_PORT..."
    if [ "$IS_ROOT" = true ]; then
        cat > "/etc/systemd/system/$SERVICE_FILE" << EOF
[Unit]
Description=Odysafe CTI Platform - Cyber Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR/cti-platform
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="CTI_PORT=$SELECTED_PORT"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/cti-platform/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=odysafe-cti-platform

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/cti-platform/uploads $INSTALL_DIR/cti-platform/outputs $INSTALL_DIR/cti-platform/database $INSTALL_DIR/cti-platform/modules $INSTALL_DIR/cti-platform/ssl

[Install]
WantedBy=multi-user.target
EOF
        if ! systemctl daemon-reload 2>/dev/null; then
            log_error "Failed to reload systemd daemon"
            exit 1
        fi
        if ! systemctl enable "$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to enable service: $SERVICE_FILE"
            exit 1
        fi
    else
        cat > "/tmp/$SERVICE_FILE" << EOF
[Unit]
Description=Odysafe CTI Platform - Cyber Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR/cti-platform
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="CTI_PORT=$SELECTED_PORT"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/cti-platform/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=odysafe-cti-platform

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/cti-platform/uploads $INSTALL_DIR/cti-platform/outputs $INSTALL_DIR/cti-platform/database $INSTALL_DIR/cti-platform/modules $INSTALL_DIR/cti-platform/ssl

[Install]
WantedBy=multi-user.target
EOF
        if ! sudo cp "/tmp/$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to copy service file to /etc/systemd/system/"
            exit 1
        fi
        rm -f "/tmp/$SERVICE_FILE" 2>/dev/null || true
        if ! sudo systemctl daemon-reload 2>/dev/null; then
            log_error "Failed to reload systemd daemon"
            exit 1
        fi
        if ! sudo systemctl enable "$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to enable service: $SERVICE_FILE"
            exit 1
        fi
    fi
    
    log_success "Systemd service installed and enabled (port: $SELECTED_PORT)"
}

# ============================================================================
# FIND FREE PORT
# ============================================================================

# Port checking function removed - using fixed port 5001

# ============================================================================
# CLEANUP EXISTING PROCESSES AND DATABASE
# ============================================================================

cleanup_before_start() {
    log_info "Cleaning up existing processes..."
    
    # Stop and remove old service completely
    if [ "$IS_ROOT" = true ]; then
        if systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null || systemctl is-failed --quiet "$SERVICE_FILE" 2>/dev/null || systemctl is-enabled --quiet "$SERVICE_FILE" 2>/dev/null; then
            log_info "Stopping and removing old service..."
            systemctl stop "$SERVICE_FILE" 2>/dev/null || true
            systemctl disable "$SERVICE_FILE" 2>/dev/null || true
            systemctl reset-failed "$SERVICE_FILE" 2>/dev/null || true
            rm -f "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
            sleep 2
        fi
    else
        if sudo systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null || sudo systemctl is-failed --quiet "$SERVICE_FILE" 2>/dev/null || sudo systemctl is-enabled --quiet "$SERVICE_FILE" 2>/dev/null; then
            log_info "Stopping and removing old service..."
            sudo systemctl stop "$SERVICE_FILE" 2>/dev/null || true
            sudo systemctl disable "$SERVICE_FILE" 2>/dev/null || true
            sudo systemctl reset-failed "$SERVICE_FILE" 2>/dev/null || true
            sudo rm -f "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null || true
            sudo systemctl daemon-reload 2>/dev/null || true
            sleep 2
        fi
    fi
    
    # Kill any orphaned Python processes running app.py
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
    
    # NOTE: Database is NOT deleted here - it should only be deleted during uninstall
    # Ensure database directory exists with correct permissions
    DB_DIR="$INSTALL_DIR/cti-platform/database"
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$DB_DIR"
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DB_DIR"
    else
        sudo mkdir -p "$DB_DIR"
        sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DB_DIR"
    fi
    
    log_success "Cleanup completed"
}

# ============================================================================
# START SERVICE
# ============================================================================

start_service() {
    log_step "Starting Odysafe CTI Platform service..."
    
    # Cleanup before starting
    cleanup_before_start
    
    # Reinstall service file with correct port (it was removed during cleanup)
    log_info "Reinstalling systemd service file..."
    
    # Force port 5001 (no port checking)
    CTI_PORT=5001
    SELECTED_PORT=5001
    
    # Create service file with dynamic port (same as in install_service)
    log_info "Creating systemd service with port $SELECTED_PORT..."
    if [ "$IS_ROOT" = true ]; then
        cat > "/etc/systemd/system/$SERVICE_FILE" << EOF
[Unit]
Description=Odysafe CTI Platform - Cyber Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR/cti-platform
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="CTI_PORT=$SELECTED_PORT"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/cti-platform/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=odysafe-cti-platform

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/cti-platform/uploads $INSTALL_DIR/cti-platform/outputs $INSTALL_DIR/cti-platform/database $INSTALL_DIR/cti-platform/modules $INSTALL_DIR/cti-platform/ssl

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > "/tmp/$SERVICE_FILE" << EOF
[Unit]
Description=Odysafe CTI Platform - Cyber Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR/cti-platform
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="CTI_PORT=$SELECTED_PORT"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/cti-platform/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=odysafe-cti-platform

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/cti-platform/uploads $INSTALL_DIR/cti-platform/outputs $INSTALL_DIR/cti-platform/database $INSTALL_DIR/cti-platform/modules $INSTALL_DIR/cti-platform/ssl

[Install]
WantedBy=multi-user.target
EOF
        if ! sudo cp "/tmp/$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to copy service file to /etc/systemd/system/"
            exit 1
        fi
        rm -f "/tmp/$SERVICE_FILE" 2>/dev/null || true
    fi
    
    # Verify service file was copied successfully
    if [ ! -f "/etc/systemd/system/$SERVICE_FILE" ]; then
        log_error "Service file was not copied successfully to /etc/systemd/system/$SERVICE_FILE"
        exit 1
    fi
    
    # Reload systemd daemon to ensure service file is up to date
    if [ "$IS_ROOT" = true ]; then
        if ! systemctl daemon-reload 2>/dev/null; then
            log_error "Failed to reload systemd daemon"
            exit 1
        fi
    else
        if ! sudo systemctl daemon-reload 2>/dev/null; then
            log_error "Failed to reload systemd daemon"
            exit 1
        fi
    fi
    
    # Enable service before starting
    if [ "$IS_ROOT" = true ]; then
        if ! systemctl enable "$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to enable service: $SERVICE_FILE"
            exit 1
        fi
    else
        if ! sudo systemctl enable "$SERVICE_FILE" 2>/dev/null; then
            log_error "Failed to enable service: $SERVICE_FILE"
            exit 1
        fi
    fi
    
    # Start service (port is already configured in the service file)
    log_info "Starting service on port 5001..."
    if [ "$IS_ROOT" = true ]; then
        if ! systemctl start "$SERVICE_FILE" 2>&1; then
            log_error "Failed to start service: $SERVICE_FILE"
            log_info "Checking service status..."
            systemctl status "$SERVICE_FILE" --no-pager -l || true
            exit 1
        fi
    else
        if ! sudo systemctl start "$SERVICE_FILE" 2>&1; then
            log_error "Failed to start service: $SERVICE_FILE"
            log_info "Checking service status..."
            sudo systemctl status "$SERVICE_FILE" --no-pager -l || true
            exit 1
        fi
    fi
    
    # Wait a moment for service to start
    sleep 5
    
    # Check service status with detailed diagnostics
    if [ "$IS_ROOT" = true ]; then
        if systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null; then
            log_success "Odysafe CTI Platform service started successfully"
        else
            log_error "Service failed to start or stopped immediately"
            log_info "Service status:"
            systemctl status "$SERVICE_FILE" --no-pager -l || true
            log_info "Recent service logs:"
            journalctl -u "$SERVICE_FILE" -n 30 --no-pager || true
            log_error "Service is not running. Please check the logs above for errors."
            exit 1
        fi
    else
        if sudo systemctl is-active --quiet "$SERVICE_FILE" 2>/dev/null; then
            log_success "Odysafe CTI Platform service started successfully"
        else
            log_error "Service failed to start or stopped immediately"
            log_info "Service status:"
            sudo systemctl status "$SERVICE_FILE" --no-pager -l || true
            log_info "Recent service logs:"
            sudo journalctl -u "$SERVICE_FILE" -n 30 --no-pager || true
            log_error "Service is not running. Please check the logs above for errors."
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
    download_ransomware_matrix
    configure_log_rotation
    install_service
    start_service
    verify_installation
    
    # Port is always 5001
    FINAL_PORT=5001
    
    echo ""
    echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}  ${GREEN}${BOLD}✓ Installation completed successfully!${NC}                          ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Service Information Section
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  SERVICE INFORMATION${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Service name:${NC}     $SERVICE_FILE"
    echo -e "  ${BOLD}Installation:${NC}     $INSTALL_DIR"
    echo -e "  ${BOLD}Port:${NC}             $FINAL_PORT"
    echo ""
    
    # Access Information Section
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  ACCESS INFORMATION${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Local access:${NC}     ${GREEN}https://localhost:$FINAL_PORT${NC}"
    echo -e "  ${BOLD}Network access:${NC}   ${GREEN}https://<SERVER_IP>:$FINAL_PORT${NC}"
    echo ""
    echo -e "  ${YELLOW}⚠${NC}  ${YELLOW}Use HTTPS (not HTTP) to access the application${NC}"
    echo -e "  ${YELLOW}⚠${NC}  ${YELLOW}Browsers will show a security warning for self-signed certificates${NC}"
    echo -e "  ${YELLOW}⚠${NC}  ${YELLOW}Click 'Advanced' → 'Proceed to localhost' to continue${NC}"
    echo ""
    
    # SSL Certificate Information Section
    SSL_DIR="$INSTALL_DIR/cti-platform/ssl"
    CERT_FILE="$SSL_DIR/cert.pem"
    KEY_FILE="$SSL_DIR/key.pem"
    
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}${BOLD}  SSL CERTIFICATE${NC}"
        echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${BOLD}Certificate:${NC}   $CERT_FILE"
        echo -e "  ${BOLD}Private key:${NC}   $KEY_FILE"
        echo ""
        echo -e "  ${YELLOW}Note:${NC} This is a self-signed certificate for development/testing."
        echo -e "       For production, replace it with your own certificate."
        echo ""
    else
        log_warning "SSL certificate was not generated. HTTPS will not be available."
        log_info "You can generate it later with: $INSTALL_DIR/generate-ssl-cert.sh"
        echo ""
    fi
    
    # Management Commands Section
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  MANAGEMENT COMMANDS${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    if [ "$IS_ROOT" = true ]; then
        echo -e "  ${BOLD}Check status:${NC}  ${GREEN}systemctl status $SERVICE_FILE${NC}"
        echo -e "  ${BOLD}View logs:${NC}     ${GREEN}journalctl -u $SERVICE_FILE -f${NC}"
        echo -e "  ${BOLD}Restart:${NC}       ${GREEN}systemctl restart $SERVICE_FILE${NC}"
        echo -e "  ${BOLD}Stop:${NC}          ${GREEN}systemctl stop $SERVICE_FILE${NC}"
    else
        echo -e "  ${BOLD}Check status:${NC}  ${GREEN}sudo systemctl status $SERVICE_FILE${NC}"
        echo -e "  ${BOLD}View logs:${NC}     ${GREEN}sudo journalctl -u $SERVICE_FILE -f${NC}"
        echo -e "  ${BOLD}Restart:${NC}       ${GREEN}sudo systemctl restart $SERVICE_FILE${NC}"
        echo -e "  ${BOLD}Stop:${NC}          ${GREEN}sudo systemctl stop $SERVICE_FILE${NC}"
    fi
    echo ""
    
    # External Resources Section (less prominent)
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  EXTERNAL RESOURCES${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  This platform integrates the following open-source tools"
    echo -e "  and resources: iocsearcher, deepdarkCTI, txt2stix,"
    echo -e "  pdfalyzer, and Ransomware Tool Matrix."
    echo ""
    echo -e "  Odysafe CTI Platform thanks the developers and maintainers"
    echo -e "  of these projects for making their tools and resources"
    echo -e "  available to the community."
    echo ""
}

# Run main function
main

