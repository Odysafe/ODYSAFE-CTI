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

# Installation paths (configurable via environment variables)
INSTALL_DIR="${CTI_INSTALL_DIR:-/opt/odysafe-cti-platform}"
SERVICE_USER="${CTI_SERVICE_USER:-odysafe-cti-platform}"
SERVICE_GROUP="${CTI_SERVICE_GROUP:-odysafe-cti-platform}"
SERVICE_FILE="odysafe-cti-platform.service"
SERVICE_FILE_SOURCE="config/odysafe-cti-platform.service"

# Port configuration (configurable via environment variable, default: 5001)
CTI_PORT="${CTI_PORT:-5001}"

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

check_network_connectivity() {
    # Check network connectivity with multiple test URLs and methods
    # Returns 0 if network is available, 1 otherwise
    local network_available=false
    local test_urls=("https://www.python.org" "https://pypi.org" "https://github.com")
    local test_url=""
    
    log_info "Checking network connectivity..."
    
    for test_url in "${test_urls[@]}"; do
        if command -v curl &>/dev/null; then
            if curl -sS --max-time 5 --connect-timeout 3 "$test_url" &>/dev/null; then
                network_available=true
                log_info "Network connectivity verified via $test_url (curl)"
                break
            fi
        elif command -v wget &>/dev/null; then
            if wget -q --spider --timeout=5 --tries=1 "$test_url" &>/dev/null; then
                network_available=true
                log_info "Network connectivity verified via $test_url (wget)"
                break
            fi
        fi
    done
    
    if [ "$network_available" = false ]; then
        log_warning "Network connectivity check failed. Some features requiring internet access may not work."
        log_info "If you're behind a proxy, ensure HTTP_PROXY and HTTPS_PROXY environment variables are set."
        return 1
    fi
    
    return 0
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
    # OS detection for Debian and Ubuntu only
    DISTRO=""
    DISTRO_VERSION=""
    DISTRO_VERSION_MINOR=""
    
    # Method 1: /etc/os-release (most reliable, POSIX standard)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        
        # Only support Debian and Ubuntu
        if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
            log_error "Unsupported operating system: $ID"
            log_error "This application only supports Debian and Ubuntu."
            log_error "Detected distribution: $PRETTY_NAME"
            return 1
        fi
        
        # Extract major and minor version numbers
        if [ -n "$VERSION_ID" ]; then
            DISTRO_VERSION_MINOR=$(echo "$VERSION_ID" | cut -d'.' -f1,2)
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
            # Only support Debian and Ubuntu
            if [ "$DISTRO" != "debian" ] && [ "$DISTRO" != "ubuntu" ]; then
                log_error "Unsupported operating system: $DISTRO"
                log_error "This application only supports Debian and Ubuntu."
                return 1
            fi
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
            else
                log_error "Unsupported operating system detected: $hctl_os"
                log_error "This application only supports Debian and Ubuntu."
                return 1
            fi
            if [ -n "$DISTRO" ]; then
                log_info "Distribution detected (hostnamectl): $DISTRO"
                # Try to get version from other methods
                if [ -z "$DISTRO_VERSION" ]; then
                    if [ -f /etc/debian_version ]; then
                        DISTRO_VERSION=$(cat /etc/debian_version)
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
    
    # If we reach here, we couldn't detect a supported OS
    log_error "Could not detect a supported operating system."
    log_error "This application only supports Debian and Ubuntu."
    log_error "Please ensure you are running on Debian or Ubuntu."
    return 1
}

detect_package_manager() {
    # Detect package manager for Debian/Ubuntu only
    local preferred_managers=("apt" "apt-get")
    
    for pm in "${preferred_managers[@]}"; do
        if command -v "$pm" &> /dev/null; then
            PKG_MANAGER="$pm"
            log_info "Package manager: $pm"
            return 0
        fi
    done
    
    log_error "No supported package manager found (${preferred_managers[*]})"
    log_error "Please ensure apt or apt-get is installed."
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
    
    # Detect package manager
    if ! detect_package_manager; then
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
                    # Check if major and minor are numeric before comparison
                    if [[ "$major" =~ ^[0-9]+$ ]] && [[ "$minor" =~ ^[0-9]+$ ]] && [ "$major" -eq 3 ] && [ "$minor" -ge 8 ]; then
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
# PACKAGE CONFIGURATION (Centralized)
# ============================================================================

get_required_packages() {
    # Centralized function to get all required packages for the current OS
    # Returns array of package names
    local packages=()
    
    case "$DISTRO" in
        debian|ubuntu)
            packages=(
                "python3"
                "python3-pip"
                "python3-dev"
                "build-essential"
                "libmagic1"
                "libmagic-dev"
                "libxml2-dev"
                "libxslt1-dev"
                "libffi-dev"
                "libssl-dev"
                "zlib1g-dev"
                "git"
                "openssl"
                "curl"
            )
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            log_error "This application only supports Debian and Ubuntu."
            packages=()
            ;;
    esac
    
    printf '%s\n' "${packages[@]}"
}

is_package_installed() {
    # Unified function to check if a package is installed
    # $1 = package name
    local pkg="$1"
    
    case "$PKG_MANAGER" in
        apt|apt-get)
            if command -v dpkg-query &>/dev/null; then
                dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" && return 0
            fi
            dpkg -l 2>/dev/null | grep -q "^ii.*${pkg}" && return 0
            return 1
            ;;
        *)
            log_warning "Unknown package manager, cannot check package: $pkg"
            return 1
            ;;
    esac
}

is_libmagic_installed() {
    # Optimized check for libmagic (runtime library)
    # Check package first, then library files, then file command
    local pkg_name=""
    
    case "$DISTRO" in
        debian|ubuntu)
            pkg_name="libmagic1"
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            return 1
            ;;
    esac
    
    # Check package
    is_package_installed "$pkg_name" && return 0
    
    # Check library files (fallback)
    [ -f "/usr/lib/x86_64-linux-gnu/libmagic.so.1" ] && return 0
    [ -f "/usr/lib/libmagic.so.1" ] && return 0
    [ -f "/lib/x86_64-linux-gnu/libmagic.so.1" ] && return 0
    
    # Check if file command works (indicates libmagic is available)
    command -v file >/dev/null 2>&1 && file --version >/dev/null 2>&1 && return 0
    
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
            *)
                log_error "Unsupported distribution: $DISTRO"
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
            *)
                log_error "Unsupported distribution: $DISTRO"
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
            *)
                log_error "Unsupported distribution: $DISTRO"
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
        local venv_available=false
        
        # Try to import venv module first (fastest check)
        if $PYTHON_CMD -c "import venv" 2>/dev/null; then
            # Try to create a test venv to verify it works
            TEST_VENV_DIR="/tmp/test_venv_$$"
            if $PYTHON_CMD -m venv "$TEST_VENV_DIR" 2>/dev/null; then
                rm -rf "$TEST_VENV_DIR" 2>/dev/null
                venv_available=true
                log_info "python3-venv: available"
            else
                log_info "python3-venv module exists but venv creation failed, will need package"
            fi
        fi
        
        if [ "$venv_available" = false ]; then
            MISSING_COMMANDS+=("python3-venv")
            case "$DISTRO" in
                debian|ubuntu)
                    # Get Python version (e.g., 3.11) and check for version-specific package
                    PYTHON_VERSION_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)
                    PYTHON_VENV_PKG="python${PYTHON_VERSION_MINOR}-venv"
                    # Check if version-specific package is installed
                    if ! is_package_installed "$PYTHON_VENV_PKG"; then
                        MISSING_PACKAGES+=("$PYTHON_VENV_PKG")
                        log_info "Need version-specific package: $PYTHON_VENV_PKG"
                    fi
                    # Also check generic python3-venv as fallback
                    if ! is_package_installed "python3-venv"; then
                        if [[ ! " ${MISSING_PACKAGES[@]} " =~ " ${PYTHON_VENV_PKG} " ]]; then
                            MISSING_PACKAGES+=("python3-venv")
                        fi
                    fi
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    ;;
            esac
        fi
    fi
    
    # Check build tools and development packages (centralized check)
    local required_packages
    mapfile -t required_packages < <(get_required_packages)
    
    for pkg in "${required_packages[@]}"; do
        # Skip Python and pip (already checked above)
        if [[ "$pkg" == "python3" ]] || [[ "$pkg" == "python3-pip" ]]; then
            continue
        fi
        
        # Special handling for libmagic1 (runtime library)
        if [[ "$pkg" == "libmagic1" ]]; then
            if ! is_libmagic_installed; then
                MISSING_PACKAGES+=("libmagic1")
            fi
            continue
        fi
        
        # Check all other packages using unified function
        if ! is_package_installed "$pkg"; then
            MISSING_PACKAGES+=("$pkg")
        fi
    done
    
    # Check openssl (for SSL certificate generation)
    if ! command -v openssl &> /dev/null; then
        MISSING_COMMANDS+=("openssl")
        case "$DISTRO" in
            debian|ubuntu)
                MISSING_PACKAGES+=("openssl")
                ;;
            *)
                log_error "Unsupported distribution: $DISTRO"
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
            else
                log_error "Unsupported distribution: $DISTRO"
                pkg_names=()
            fi
            ;;
        python3-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("python3-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        build-essential)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("build-essential")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        libmagic1)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("libmagic1")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        libmagic-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("libmagic-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        libxml2-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("libxml2-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        libxslt1-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("libxslt1-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        libffi-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("libffi-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        libssl-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("libssl-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        zlib1g-dev)
            case "$DISTRO" in
                debian|ubuntu)
                    pkg_names=("zlib1g-dev")
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        python3-venv)
            case "$DISTRO" in
                debian|ubuntu)
                    # Try version-specific first, then generic
                    if [ -n "$PYTHON_VERSION" ]; then
                        PYTHON_VERSION_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f1,2)
                        pkg_names=("python${PYTHON_VERSION_MINOR}-venv" "python3-venv")
                    else
                        pkg_names=("python3-venv")
                    fi
                    ;;
                *)
                    log_error "Unsupported distribution: $DISTRO"
                    pkg_names=()
                    ;;
            esac
            ;;
        git|openssl|curl)
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
    
    # Check if already installed using unified function
    for pkg_name in "${pkg_names[@]}"; do
        if is_package_installed "$pkg_name"; then
            log_info "$generic_pkg is already installed (as $pkg_name)"
            return 0
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
    
    # Update package list with retry (only once, not per package)
    local update_needed=true
    if [ "$PKG_MANAGER" = "apt" ] || [ "$PKG_MANAGER" = "apt-get" ]; then
        log_info "Updating package list..."
        if execute_with_retry "$PKG_MANAGER update" 3 5 false; then
            update_needed=false
        else
            log_warning "Package list update failed, but continuing with installation..."
        fi
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        # EPEL not needed for Debian/Ubuntu
        if false; then
            if ! rpm -q epel-release &>/dev/null; then
                log_info "EPEL repository not found, but continuing..."
            fi
        fi
        update_needed=false
    fi
    
    # Try to install all packages at once first (faster)
    log_info "Installing packages: ${MISSING_PACKAGES[*]}"
    local failed_packages=()
    local install_cmd_packages=()
    
    # Build install command with all packages (use first available name for each)
    for pkg in "${MISSING_PACKAGES[@]}"; do
        # Get OS-specific package name (use first one)
        local pkg_name
        pkg_name=$(get_package_name_for_os "$pkg" | head -1)
        if [ -n "$pkg_name" ]; then
            # Skip if already installed
            if ! is_package_installed "$pkg_name"; then
                install_cmd_packages+=("$pkg_name")
            fi
        fi
    done
    
    # Try bulk installation first (much faster) if we have packages to install
    if [ ${#install_cmd_packages[@]} -gt 0 ]; then
        log_info "Attempting bulk installation of ${#install_cmd_packages[@]} packages..."
        local bulk_cmd="$INSTALL_CMD ${install_cmd_packages[*]}"
        if execute_with_retry "$bulk_cmd" 2 3 false; then
            log_success "All packages installed successfully in bulk"
        else
            log_warning "Bulk installation failed, trying packages individually..."
            # Fall back to individual installation with retry logic
            for pkg in "${MISSING_PACKAGES[@]}"; do
                if ! install_system_package_robust "$pkg"; then
                    failed_packages+=("$pkg")
                    log_warning "Failed to install $pkg, but continuing with other packages..."
                fi
            done
        fi
    else
        log_info "All packages appear to be already installed"
    fi
    
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_error "Failed to install some prerequisites: ${failed_packages[*]}"
        log_error "Please install manually: $INSTALL_CMD ${failed_packages[*]}"
        log_info "Common causes for package installation failures:"
        log_info "  - Network connectivity issues (check internet connection)"
        log_info "  - Repository configuration problems (run: $PKG_MANAGER update)"
        log_info "  - Insufficient disk space (check with: df -h)"
        log_info "  - Permission problems (ensure you have sudo/root access)"
        # Don't exit immediately, continue to see if we can work without them
        log_warning "Continuing installation, but some features may not work..."
    fi
    
    # Re-detect Python and pip after installation
    set +e  # Temporarily disable error exit for detection
    if ! detect_python; then
        log_error "Python installation failed"
        set -e
        exit 1
    fi
    
    if ! detect_pip; then
        log_info "pip not found, attempting to install..."
        if ! install_pip_robust "$PYTHON_CMD"; then
            log_error "pip installation failed"
            set -e
            exit 1
        fi
    fi
    
    # Re-verify git after installation (refresh PATH cache)
    # Clear command hash cache to ensure newly installed commands are found
    hash -r 2>/dev/null || true
    
    # Verify git is now available
    if ! command -v git &>/dev/null; then
        # Try to find git in common locations and add to PATH
        local git_found=false
        if [ -f /usr/bin/git ]; then
            log_info "Git found at /usr/bin/git, adding to PATH"
            export PATH="/usr/bin:$PATH"
            git_found=true
        elif [ -f /usr/local/bin/git ]; then
            log_info "Git found at /usr/local/bin/git, adding to PATH"
            export PATH="/usr/local/bin:$PATH"
            git_found=true
        fi
        
        # Verify git is now accessible
        if [ "$git_found" = true ] && command -v git &>/dev/null; then
            log_info "Git verified: $(git --version 2>/dev/null || echo 'installed')"
        else
            log_error "Git installation failed or git is not available in PATH"
            log_error "Please install git manually: $INSTALL_CMD git"
            log_error "Or verify git installation: which git"
            set -e
            exit 1
        fi
    else
        log_info "Git verified: $(git --version 2>/dev/null || echo 'installed')"
    fi
    
    set -e  # Re-enable error exit
    
    log_success "Prerequisites installed successfully"
}

# ============================================================================
# SERVICE USER CREATION
# ============================================================================

create_service_user() {
    log_step "Creating service user and group..."
    
    # Check if user already exists
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "Service user already exists: $SERVICE_USER"
        
        # Verify user properties are correct
        local user_home=$(getent passwd "$SERVICE_USER" | cut -d: -f6)
        local user_shell=$(getent passwd "$SERVICE_USER" | cut -d: -f7)
        
        # Check if user is system user (UID < 1000 on Debian/Ubuntu)
        local user_uid=$(id -u "$SERVICE_USER" 2>/dev/null || echo "0")
        local is_system_user=false
        if [ "$user_uid" -lt 1000 ] || ([ -f /etc/redhat-release ] && [ "$user_uid" -lt 500 ]); then
            is_system_user=true
        fi
        
        if [ "$is_system_user" = false ]; then
            log_warning "User $SERVICE_USER exists but is not a system user (UID: $user_uid)"
            log_warning "This may cause issues. Consider removing the user and re-running installation."
        fi
        
        if [ "$user_shell" != "/bin/false" ] && [ "$user_shell" != "/usr/sbin/nologin" ] && [ "$user_shell" != "/sbin/nologin" ]; then
            log_warning "User $SERVICE_USER has shell $user_shell (expected /bin/false or nologin)"
        fi
        
        # User exists and seems acceptable, continue
        return 0
    fi
    
    # User doesn't exist, create it
    log_info "Creating service user: $SERVICE_USER"
    local user_created=false
    
    # Method 1: Try with useradd and home directory
    if [ "$IS_ROOT" = true ]; then
        if useradd -r -s /bin/false -d "$INSTALL_DIR" -c "Odysafe CTI Platform Service User" "$SERVICE_USER" 2>/dev/null; then
            user_created=true
        fi
    else
        if sudo useradd -r -s /bin/false -d "$INSTALL_DIR" -c "Odysafe CTI Platform Service User" "$SERVICE_USER" 2>/dev/null; then
            user_created=true
        fi
    fi
    
    # Method 2: Try without -d option if Method 1 failed
    if [ "$user_created" = false ]; then
        log_warning "Failed to create user with home directory, trying without..."
        if [ "$IS_ROOT" = true ]; then
            if useradd -r -s /bin/false -c "Odysafe CTI Platform Service User" "$SERVICE_USER" 2>/dev/null; then
                user_created=true
            fi
        else
            if sudo useradd -r -s /bin/false -c "Odysafe CTI Platform Service User" "$SERVICE_USER" 2>/dev/null; then
                user_created=true
            fi
        fi
    fi
    
    # Method 3: Try with /usr/sbin/nologin as shell (some systems prefer this)
    if [ "$user_created" = false ]; then
        log_warning "Failed with /bin/false, trying /usr/sbin/nologin..."
        if [ "$IS_ROOT" = true ]; then
            if useradd -r -s /usr/sbin/nologin -c "Odysafe CTI Platform Service User" "$SERVICE_USER" 2>/dev/null; then
                user_created=true
            fi
        else
            if sudo useradd -r -s /usr/sbin/nologin -c "Odysafe CTI Platform Service User" "$SERVICE_USER" 2>/dev/null; then
                user_created=true
            fi
        fi
    fi
    
    if [ "$user_created" = true ]; then
        log_success "Service user created: $SERVICE_USER"
    else
        log_error "Failed to create service user: $SERVICE_USER after all methods"
        log_error "Please check system logs for details or create the user manually:"
        log_error "  useradd -r -s /bin/false -d $INSTALL_DIR $SERVICE_USER"
        exit 1
    fi
    
    # Ensure service group exists (create if needed)
    if ! getent group "$SERVICE_GROUP" &>/dev/null; then
        log_info "Creating service group: $SERVICE_GROUP"
        if [ "$IS_ROOT" = true ]; then
            if ! groupadd -r "$SERVICE_GROUP" 2>/dev/null; then
                log_warning "Failed to create group $SERVICE_GROUP, but continuing..."
            else
                log_success "Service group created: $SERVICE_GROUP"
            fi
        else
            if ! sudo groupadd -r "$SERVICE_GROUP" 2>/dev/null; then
                log_warning "Failed to create group $SERVICE_GROUP, but continuing..."
            else
                log_success "Service group created: $SERVICE_GROUP"
            fi
        fi
    else
        log_info "Service group already exists: $SERVICE_GROUP"
    fi
    
    # Add user to group if not already member
    if getent group "$SERVICE_GROUP" | grep -q "$SERVICE_USER"; then
        log_info "User $SERVICE_USER is already a member of group $SERVICE_GROUP"
    else
        log_info "Adding user $SERVICE_USER to group $SERVICE_GROUP"
        if [ "$IS_ROOT" = true ]; then
            usermod -a -G "$SERVICE_GROUP" "$SERVICE_USER" 2>/dev/null || log_warning "Failed to add user to group"
        else
            sudo usermod -a -G "$SERVICE_GROUP" "$SERVICE_USER" 2>/dev/null || log_warning "Failed to add user to group"
        fi
    fi
}

# ============================================================================
# INSTALL APPLICATION FILES
# ============================================================================

install_files() {
    log_step "Installing application files to $INSTALL_DIR..."
    
    # Create installation directory
    if [ "$IS_ROOT" = true ]; then
        if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            log_error "Failed to create installation directory: $INSTALL_DIR"
            exit 1
        fi
    else
        if ! sudo mkdir -p "$INSTALL_DIR" 2>/dev/null; then
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
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/cti-platform" 2>/dev/null || true
            else
                sudo rm -rf "$INSTALL_DIR/cti-platform" 2>/dev/null || true
            fi
        fi
        if [ -d "$INSTALL_DIR/dependencies/repos" ]; then
            if [ "$IS_ROOT" = true ]; then
                rm -rf "$INSTALL_DIR/dependencies/repos" 2>/dev/null || true
            else
                sudo rm -rf "$INSTALL_DIR/dependencies/repos" 2>/dev/null || true
            fi
        fi
        if [ -f "$INSTALL_DIR/scripts/requirements.txt" ]; then
            if [ "$IS_ROOT" = true ]; then
                rm -f "$INSTALL_DIR/scripts/requirements.txt" 2>/dev/null || true
            else
                sudo rm -f "$INSTALL_DIR/scripts/requirements.txt" 2>/dev/null || true
            fi
        fi
    fi
    
    # Copy new files with error handling (use rsync if available for incremental copy)
    log_info "Copying application files..."
    if command -v rsync &>/dev/null; then
        # Use rsync for incremental copy (only changed files)
        log_info "Using rsync for efficient file copying..."
        # Create destination directory before rsync
        if [ "$IS_ROOT" = true ]; then
            mkdir -p "$INSTALL_DIR/cti-platform" 2>/dev/null || {
                log_error "Failed to create cti-platform directory"
                exit 1
            }
        else
            sudo mkdir -p "$INSTALL_DIR/cti-platform" 2>/dev/null || {
                log_error "Failed to create cti-platform directory"
                exit 1
            }
        fi
        if [ "$IS_ROOT" = true ]; then
            rsync -a --update --delete "$SCRIPT_DIR/cti-platform/" "$INSTALL_DIR/cti-platform/" || {
                log_error "Failed to copy cti-platform directory with rsync"
                exit 1
            }
        else
            sudo rsync -a --update --delete "$SCRIPT_DIR/cti-platform/" "$INSTALL_DIR/cti-platform/" || {
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
    # Check if source directory exists before copying
    if [ -d "$SCRIPT_DIR/dependencies/repos" ]; then
        # Create destination directory before copy
        if [ "$IS_ROOT" = true ]; then
            mkdir -p "$INSTALL_DIR/dependencies/repos" 2>/dev/null || {
                log_error "Failed to create dependencies/repos directory"
                exit 1
            }
        else
            sudo mkdir -p "$INSTALL_DIR/dependencies/repos" 2>/dev/null || {
                log_error "Failed to create dependencies/repos directory"
                exit 1
            }
        fi
        
        if command -v rsync &>/dev/null; then
            # Check if source directory has content
            if [ "$(ls -A "$SCRIPT_DIR/dependencies/repos" 2>/dev/null)" ]; then
                if [ "$IS_ROOT" = true ]; then
                    rsync -a --update "$SCRIPT_DIR/dependencies/repos/" "$INSTALL_DIR/dependencies/repos/" || {
                        log_error "Failed to copy repos directory with rsync"
                        exit 1
                    }
                else
                    sudo rsync -a --update "$SCRIPT_DIR/dependencies/repos/" "$INSTALL_DIR/dependencies/repos/" || {
                        log_error "Failed to copy repos directory with rsync"
                        exit 1
                    }
                fi
            else
                log_info "dependencies/repos directory is empty, skipping copy"
            fi
        else
            # Fallback to cp if rsync not available
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
    else
        log_info "dependencies/repos directory doesn't exist in source, skipping copy"
    fi
    
    # Copy requirements.txt only if different or missing
    if [ ! -d "$INSTALL_DIR/scripts" ]; then
        if [ "$IS_ROOT" = true ]; then
            mkdir -p "$INSTALL_DIR/scripts" 2>/dev/null || {
                log_error "Failed to create scripts directory"
                exit 1
            }
        else
            sudo mkdir -p "$INSTALL_DIR/scripts" 2>/dev/null || {
                log_error "Failed to create scripts directory"
                exit 1
            }
        fi
    fi
    if [ ! -f "$INSTALL_DIR/scripts/requirements.txt" ] || ! cmp -s "$SCRIPT_DIR/scripts/requirements.txt" "$INSTALL_DIR/scripts/requirements.txt" 2>/dev/null; then
        if ! cp "$SCRIPT_DIR/scripts/requirements.txt" "$INSTALL_DIR/scripts/" 2>/dev/null; then
            if [ "$IS_ROOT" = false ]; then
                if ! sudo cp "$SCRIPT_DIR/scripts/requirements.txt" "$INSTALL_DIR/scripts/" 2>/dev/null; then
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
                mkdir -p "$INSTALL_DIR/cti-platform/database" 2>/dev/null || true
                cp -r "$TEMP_BACKUP/database"/* "$INSTALL_DIR/cti-platform/database/" 2>/dev/null || true
            else
                sudo mkdir -p "$INSTALL_DIR/cti-platform/database" 2>/dev/null || true
                sudo cp -r "$TEMP_BACKUP/database"/* "$INSTALL_DIR/cti-platform/database/" 2>/dev/null || true
            fi
            log_info "Database restored"
        fi
        
        # Restore uploads
        if [ -d "$TEMP_BACKUP/uploads" ]; then
            if [ "$IS_ROOT" = true ]; then
                mkdir -p "$INSTALL_DIR/cti-platform/uploads" 2>/dev/null || true
                cp -r "$TEMP_BACKUP/uploads"/* "$INSTALL_DIR/cti-platform/uploads/" 2>/dev/null || true
            else
                sudo mkdir -p "$INSTALL_DIR/cti-platform/uploads" 2>/dev/null || true
                sudo cp -r "$TEMP_BACKUP/uploads"/* "$INSTALL_DIR/cti-platform/uploads/" 2>/dev/null || true
            fi
            log_info "Uploads restored"
        fi
        
        # Restore outputs
        if [ -d "$TEMP_BACKUP/outputs" ]; then
            if [ "$IS_ROOT" = true ]; then
                mkdir -p "$INSTALL_DIR/cti-platform/outputs" 2>/dev/null || true
                cp -r "$TEMP_BACKUP/outputs"/* "$INSTALL_DIR/cti-platform/outputs/" 2>/dev/null || true
            else
                sudo mkdir -p "$INSTALL_DIR/cti-platform/outputs" 2>/dev/null || true
                sudo cp -r "$TEMP_BACKUP/outputs"/* "$INSTALL_DIR/cti-platform/outputs/" 2>/dev/null || true
            fi
            log_info "Outputs restored"
        fi
        
        # Restore cache
        if [ -d "$TEMP_BACKUP/cache" ]; then
            if [ "$IS_ROOT" = true ]; then
                mkdir -p "$INSTALL_DIR/cti-platform/modules/cache" 2>/dev/null || true
                cp -r "$TEMP_BACKUP/cache"/* "$INSTALL_DIR/cti-platform/modules/cache/" 2>/dev/null || true
            else
                sudo mkdir -p "$INSTALL_DIR/cti-platform/modules/cache" 2>/dev/null || true
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
            # First check network connectivity with multiple methods
            NETWORK_AVAILABLE=false
            local network_test_urls=("https://www.python.org" "https://pypi.org")
            
            for test_url in "${network_test_urls[@]}"; do
                if command -v curl &>/dev/null; then
                    if curl -sS --max-time 5 --connect-timeout 3 "$test_url" &>/dev/null; then
                        NETWORK_AVAILABLE=true
                        log_info "Network connectivity verified via $test_url"
                        break
                    fi
                elif command -v wget &>/dev/null; then
                    if wget -q --spider --timeout=5 --tries=1 "$test_url" &>/dev/null; then
                        NETWORK_AVAILABLE=true
                        log_info "Network connectivity verified via $test_url"
                        break
                    fi
                fi
            done
            
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
    
    # Upgrade pip, setuptools, wheel with retry and cache optimization
    log_info "Upgrading pip, setuptools, wheel..."
    local pip_cache_dir="$INSTALL_DIR/.pip_cache"
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$pip_cache_dir" 2>/dev/null || true
    else
        sudo mkdir -p "$pip_cache_dir" 2>/dev/null || true
    fi
    
    if ! execute_with_retry "$PIP_CMD install --upgrade pip setuptools wheel --cache-dir \"$pip_cache_dir\" --quiet" 3 2 false; then
        log_warning "Failed to upgrade pip with retry, trying without --quiet for diagnostics..."
        $PIP_CMD install --upgrade pip setuptools wheel --cache-dir "$pip_cache_dir" 2>&1 | head -20
        log_error "Failed to upgrade pip, setuptools, wheel"
        log_info "Possible causes: network issues, disk space, or permission problems"
        log_info "Check network connectivity and ensure you have write permissions to $INSTALL_DIR"
        exit 1
    fi
    
    # Install main dependencies with retry and cache optimization
    log_info "Installing main dependencies from requirements.txt..."
    if ! execute_with_retry "$PIP_CMD install -r scripts/requirements.txt --cache-dir \"$pip_cache_dir\" --quiet" 3 5 false; then
        log_warning "Failed to install dependencies with retry, trying without --quiet for diagnostics..."
        $PIP_CMD install -r scripts/requirements.txt --cache-dir "$pip_cache_dir" 2>&1 | tail -30
        log_error "Failed to install main dependencies"
        log_info "Possible causes:"
        log_info "  - Missing system dependencies (build-essential, python3-dev, etc.)"
        log_info "  - Network connectivity issues"
        log_info "  - Insufficient disk space"
        log_info "  - Permission problems"
        log_info "Check the error messages above for specific package failures"
        exit 1
    fi
    
    # Verify iocsearcher installation (installed via pip from requirements.txt)
    log_info "Verifying iocsearcher installation..."
    if ! $PIP_CMD show iocsearcher &>/dev/null; then
        log_warning "iocsearcher not found in pip packages, but installation will continue"
        log_info "The application will attempt to use local fallback if available"
    else
        IOCSEARCHER_VERSION=$($PIP_CMD show iocsearcher 2>/dev/null | grep "^Version:" | awk '{print $2}' || echo "unknown")
        log_success "iocsearcher installed (version: $IOCSEARCHER_VERSION)"
    fi
    
    
    # Note: STIX Graph visualization uses the PNG icon version from cti-platform/static/js/stix2viz/stix2viz.js
    
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
    
    # Create directories with error handling (only if they don't exist)
    local dirs=("uploads" "outputs/iocs" "outputs/stix" "outputs/reports" "database" "modules/cache" "ssl")
    local dir_created=true
    local dirs_created=0
    local dirs_skipped=0
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            dirs_skipped=$((dirs_skipped + 1))
            continue
        fi
        
        if [ "$IS_ROOT" = true ]; then
            if ! mkdir -p "$dir" 2>/dev/null; then
                log_error "Failed to create directory: $dir"
                dir_created=false
            else
                dirs_created=$((dirs_created + 1))
            fi
        else
            if ! sudo mkdir -p "$dir" 2>/dev/null; then
                log_error "Failed to create directory: $dir"
                dir_created=false
            else
                dirs_created=$((dirs_created + 1))
            fi
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

download_git_repo() {
    # Download a Git repository with improved error handling and integrity verification
    # Usage: download_git_repo "repo_url" "target_dir" "repo_name" "run_as_user" ["expected_sha256"]
    local repo_url="$1"
    local target_dir="$2"
    local repo_name="$3"
    local run_as_user="${4:-$SERVICE_USER}"
    local expected_sha256="${5:-}"
    local output=""
    local exit_code=1
    local clone_success=false
    
    # Check if git is available
    if ! command -v git &>/dev/null; then
        log_error "Git is not installed. Cannot download $repo_name."
        log_info "Install git: $INSTALL_CMD git"
        return 1
    fi
    
    # Skip if already exists and verify integrity if checksum provided
    if [ -d "$target_dir" ] && [ -d "$target_dir/.git" ]; then
        log_info "$repo_name repository already exists"
        
        # Verify integrity if checksum is provided (run as service user)
        if [ -n "$expected_sha256" ] && command -v sha256sum &>/dev/null; then
            local current_sha256=""
            local sha_cmd="cd \"$target_dir\" && git rev-parse HEAD 2>/dev/null | sha256sum | awk '{print \$1}'"
            
            if [ "$IS_ROOT" = true ] && id "$run_as_user" &>/dev/null; then
                current_sha256=$(su -s /bin/bash -c "$sha_cmd" "$run_as_user" 2>/dev/null || echo "")
            elif [ "$IS_ROOT" = false ] && id "$run_as_user" &>/dev/null; then
                current_sha256=$(sudo -u "$run_as_user" bash -c "$sha_cmd" 2>/dev/null || echo "")
            else
                current_sha256=$(cd "$target_dir" && git rev-parse HEAD 2>/dev/null | sha256sum | awk '{print $1}' || echo "")
            fi
            
            if [ -n "$current_sha256" ] && [ "$current_sha256" != "$expected_sha256" ]; then
                log_warning "Repository checksum mismatch. Re-downloading..."
                if [ "$IS_ROOT" = true ]; then
                    rm -rf "$target_dir" 2>/dev/null || true
                else
                    sudo rm -rf "$target_dir" 2>/dev/null || true
                fi
            elif [ -n "$current_sha256" ]; then
                log_info "Repository integrity verified, skipping download"
                log_info "Use the web interface to update it if needed"
                return 0
            else
                log_warning "Could not verify repository checksum, but repository exists"
                log_info "Skipping download (use the web interface to update if needed)"
                return 0
            fi
        else
            log_info "Skipping download (use the web interface to update if needed)"
            return 0
        fi
    fi
    
    # Create parent directory
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$(dirname "$target_dir")" 2>/dev/null || {
            log_error "Failed to create parent directory for $repo_name"
            return 1
        }
    else
        sudo mkdir -p "$(dirname "$target_dir")" 2>/dev/null || {
            log_error "Failed to create parent directory for $repo_name"
            return 1
        }
    fi
    
    # Check network connectivity before attempting download
    if ! check_network_connectivity; then
        log_warning "Network connectivity check failed. $repo_name download skipped."
        log_info "You can download it later via the web interface or manually with:"
        log_info "  git clone $repo_url $target_dir"
        return 1
    fi
    
    # Try to download with retry logic
    log_info "Downloading $repo_name repository..."
    local attempt=1
    local max_attempts=3
    
    while [ $attempt -le $max_attempts ] && [ "$clone_success" = false ]; do
        if [ $attempt -gt 1 ]; then
            log_info "Retrying $repo_name download (attempt $attempt/$max_attempts)..."
            sleep $((attempt * 2))
        fi
        
        # Download as specified user
        if [ "$IS_ROOT" = true ]; then
            if id "$run_as_user" &>/dev/null; then
                output=$(su -s /bin/bash -c "git clone --depth 1 \"$repo_url\" \"$target_dir\" 2>&1" "$run_as_user" 2>&1)
                exit_code=$?
            else
                output=$(git clone --depth 1 "$repo_url" "$target_dir" 2>&1)
                exit_code=$?
            fi
        else
            if id "$run_as_user" &>/dev/null; then
                output=$(sudo -u "$run_as_user" git clone --depth 1 "$repo_url" "$target_dir" 2>&1)
                exit_code=$?
            else
                output=$(git clone --depth 1 "$repo_url" "$target_dir" 2>&1)
                exit_code=$?
            fi
        fi
        
        if [ $exit_code -eq 0 ]; then
            clone_success=true
        else
            log_warning "Git clone attempt $attempt failed for $repo_name"
            if echo "$output" | grep -qi "fatal:.*repository.*not found"; then
                log_error "Repository not found: $repo_url"
                log_info "Please verify the repository URL is correct"
                return 1
            elif echo "$output" | grep -qi "fatal:.*authentication failed"; then
                log_error "Authentication failed for $repo_url"
                log_info "If this is a private repository, ensure credentials are configured"
                return 1
            elif echo "$output" | grep -qi "fatal:.*could not resolve host"; then
                log_error "Could not resolve host. Check your network connection and DNS settings."
                return 1
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    if [ "$clone_success" = true ]; then
        # Verify repository integrity: check that it was actually cloned
        if [ ! -d "$target_dir" ] || [ ! -d "$target_dir/.git" ]; then
            log_error "Repository directory or .git folder missing after clone"
            return 1
        fi
        
        # Verify repository has content (not empty)
        local file_count=$(find "$target_dir" -type f -not -path "$target_dir/.git/*" 2>/dev/null | wc -l)
        if [ "$file_count" -eq 0 ]; then
            log_warning "Repository appears to be empty (no files found)"
            log_info "This may be normal for some repositories, continuing..."
        else
            log_info "Repository contains $file_count files"
        fi
        
        # Verify git repository is valid (run as the same user who cloned it)
        local git_check_cmd="cd \"$target_dir\" && git rev-parse --git-dir >/dev/null 2>&1"
        local git_check_result=1
        
        if [ "$IS_ROOT" = true ] && id "$run_as_user" &>/dev/null; then
            # Run git check as the service user
            if su -s /bin/bash -c "$git_check_cmd" "$run_as_user" 2>/dev/null; then
                git_check_result=0
            fi
        elif [ "$IS_ROOT" = false ] && id "$run_as_user" &>/dev/null; then
            # Run git check as the service user with sudo
            if sudo -u "$run_as_user" bash -c "$git_check_cmd" 2>/dev/null; then
                git_check_result=0
            fi
        else
            # Fallback: try as current user
            if (cd "$target_dir" && git rev-parse --git-dir >/dev/null 2>&1); then
                git_check_result=0
            fi
        fi
        
        # If git check failed, try a simpler verification (just check .git exists and has content)
        if [ $git_check_result -ne 0 ]; then
            log_warning "Git repository validation check failed, but .git directory exists"
            log_info "This may be due to shallow clone or permissions. Verifying basic structure..."
            if [ -d "$target_dir/.git" ] && [ -f "$target_dir/.git/HEAD" ]; then
                log_info "Repository structure appears valid (.git/HEAD exists)"
                git_check_result=0
            else
                log_error "Repository structure is invalid (.git/HEAD missing)"
                return 1
            fi
        fi
        
        # Verify repository integrity if checksum provided (run as service user)
        if [ -n "$expected_sha256" ] && command -v sha256sum &>/dev/null; then
            log_info "Verifying repository integrity with checksum..."
            local repo_sha256=""
            local sha_cmd="cd \"$target_dir\" && git rev-parse HEAD 2>/dev/null | sha256sum | awk '{print \$1}'"
            
            if [ "$IS_ROOT" = true ] && id "$run_as_user" &>/dev/null; then
                repo_sha256=$(su -s /bin/bash -c "$sha_cmd" "$run_as_user" 2>/dev/null || echo "")
            elif [ "$IS_ROOT" = false ] && id "$run_as_user" &>/dev/null; then
                repo_sha256=$(sudo -u "$run_as_user" bash -c "$sha_cmd" 2>/dev/null || echo "")
            else
                repo_sha256=$(cd "$target_dir" && git rev-parse HEAD 2>/dev/null | sha256sum | awk '{print $1}' || echo "")
            fi
            
            if [ -n "$repo_sha256" ] && [ "$repo_sha256" != "$expected_sha256" ]; then
                log_warning "Repository checksum mismatch (expected: $expected_sha256, got: $repo_sha256)"
                log_warning "Repository may have been modified or corrupted"
                log_info "Continuing anyway, but verify repository contents manually"
            elif [ -n "$repo_sha256" ]; then
                log_success "Repository integrity verified with checksum"
            fi
        fi
        
        # Set ownership
        if [ -d "$target_dir" ]; then
            if [ "$IS_ROOT" = true ]; then
                chown -R "$SERVICE_USER:$SERVICE_GROUP" "$target_dir" 2>/dev/null || true
            else
                sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$target_dir" 2>/dev/null || true
            fi
        fi
        log_success "$repo_name repository downloaded and verified successfully"
        return 0
    else
        log_error "Failed to download $repo_name repository after $max_attempts attempts"
        log_error "Last error output:"
        echo "$output" | while IFS= read -r line; do
            log_error "  $line"
        done
        log_info "You can download it later via the web interface or manually with:"
        log_info "  git clone $repo_url $target_dir"
        return 1
    fi
}

download_deepdarkcti() {
    log_step "Downloading DeepDarkCTI repository..."
    
    DEEPDARKCTI_REPO_URL="https://github.com/fastfire/deepdarkCTI.git"
    DEEPDARKCTI_DIR="$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main"
    
    download_git_repo "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" "DeepDarkCTI" "$SERVICE_USER" || {
        log_warning "DeepDarkCTI repository download failed, but installation will continue"
        log_info "You can download it later via the web interface"
    }
}

# ============================================================================
# DOWNLOAD RANSOMWARE TOOL MATRIX
# ============================================================================

download_ransomware_matrix() {
    log_step "Downloading Ransomware Tool Matrix repository..."
    
    RTM_REPO_URL="https://github.com/BushidoUK/Ransomware-Tool-Matrix.git"
    RTM_DIR="$INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main"
    
    download_git_repo "$RTM_REPO_URL" "$RTM_DIR" "Ransomware Tool Matrix" "$SERVICE_USER" || {
        log_warning "Ransomware Tool Matrix repository download failed, but installation will continue"
        log_info "You can download it later via the web interface"
    }
}

download_external_repositories() {
    # Download external repositories in parallel for faster installation
    log_step "Downloading external repositories..."
    
    DEEPDARKCTI_REPO_URL="https://github.com/fastfire/deepdarkCTI.git"
    DEEPDARKCTI_DIR="$INSTALL_DIR/cti-platform/modules/deepdarkCTI-main"
    RTM_REPO_URL="https://github.com/BushidoUK/Ransomware-Tool-Matrix.git"
    RTM_DIR="$INSTALL_DIR/cti-platform/modules/Ransomware-Tool-Matrix-main"
    
    # Check if both repositories need to be downloaded
    local need_deepdarkcti=false
    local need_rtm=false
    
    if [ ! -d "$DEEPDARKCTI_DIR" ] || [ ! -d "$DEEPDARKCTI_DIR/.git" ]; then
        need_deepdarkcti=true
    fi
    
    if [ ! -d "$RTM_DIR" ] || [ ! -d "$RTM_DIR/.git" ]; then
        need_rtm=true
    fi
    
    # If neither needs downloading, skip
    if [ "$need_deepdarkcti" = false ] && [ "$need_rtm" = false ]; then
        log_info "All external repositories already exist, skipping download"
        return 0
    fi
    
    # Check network connectivity once
    if ! check_network_connectivity; then
        log_warning "Network connectivity check failed. External repository downloads skipped."
        log_info "You can download them later via the web interface"
        return 1
    fi
    
    # Check if git is available
    if ! command -v git &>/dev/null; then
        log_error "Git is not installed. Cannot download external repositories."
        log_info "Install git: $INSTALL_CMD git"
        return 1
    fi
    
    local overall_success=true
    local deepdarkcti_result=0
    local rtm_result=0
    
    # Download in parallel if both are needed, otherwise download sequentially
    if [ "$need_deepdarkcti" = true ] && [ "$need_rtm" = true ]; then
        log_info "Downloading repositories in parallel for faster installation..."
        
        # Create temporary log files with unique names
        local log_dir="${TMPDIR:-/tmp}"
        local deepdarkcti_log="${log_dir}/deepdarkcti_download_$$.log"
        local rtm_log="${log_dir}/rtm_download_$$.log"
        
        # Start both downloads in background with error handling
        set +e  # Disable error exit for background processes
        (download_git_repo "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" "DeepDarkCTI" "$SERVICE_USER" > "$deepdarkcti_log" 2>&1) &
        local deepdarkcti_pid=$!
        
        (download_git_repo "$RTM_REPO_URL" "$RTM_DIR" "Ransomware Tool Matrix" "$SERVICE_USER" > "$rtm_log" 2>&1) &
        local rtm_pid=$!
        set -e  # Re-enable error exit
        
        # Wait for both to complete and capture exit codes
        wait $deepdarkcti_pid 2>/dev/null || deepdarkcti_result=$?
        wait $rtm_pid 2>/dev/null || rtm_result=$?
        
        # Display results with detailed error information
        if [ $deepdarkcti_result -eq 0 ]; then
            log_success "DeepDarkCTI repository downloaded successfully"
        else
            log_warning "DeepDarkCTI repository download failed"
            if [ -f "$deepdarkcti_log" ]; then
                log_info "Error details (last 5 lines):"
                tail -5 "$deepdarkcti_log" | while IFS= read -r line; do
                    log_warning "  $line"
                done
            fi
            overall_success=false
        fi
        
        if [ $rtm_result -eq 0 ]; then
            log_success "Ransomware Tool Matrix repository downloaded successfully"
        else
            log_warning "Ransomware Tool Matrix repository download failed"
            if [ -f "$rtm_log" ]; then
                log_info "Error details (last 5 lines):"
                tail -5 "$rtm_log" | while IFS= read -r line; do
                    log_warning "  $line"
                done
            fi
            overall_success=false
        fi
        
        # Cleanup log files
        rm -f "$deepdarkcti_log" "$rtm_log" 2>/dev/null || true
        
        if [ "$overall_success" = true ]; then
            return 0
        else
            return 1
        fi
    else
        # Download sequentially if only one is needed
        local download_failed=false
        if [ "$need_deepdarkcti" = true ]; then
            if ! download_git_repo "$DEEPDARKCTI_REPO_URL" "$DEEPDARKCTI_DIR" "DeepDarkCTI" "$SERVICE_USER"; then
                log_warning "DeepDarkCTI repository download failed, but continuing..."
                download_failed=true
            fi
        fi
        
        if [ "$need_rtm" = true ]; then
            if ! download_git_repo "$RTM_REPO_URL" "$RTM_DIR" "Ransomware Tool Matrix" "$SERVICE_USER"; then
                log_warning "Ransomware Tool Matrix repository download failed, but continuing..."
                download_failed=true
            fi
        fi
        
        if [ "$download_failed" = true ]; then
            log_info "Some repositories failed to download. You can download them later via the web interface."
            return 1
        fi
        
        return 0
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
        log_info "You can generate it later with: $INSTALL_DIR/scripts/generate-ssl-cert.sh"
    fi
}

# ============================================================================
# SETUP CERTIFICATE RENEWAL
# ============================================================================

setup_certificate_renewal() {
    log_step "Setting up automatic SSL certificate renewal..."
    
    # Copy certificate generation script
    if [ -f "$SCRIPT_DIR/scripts/generate-ssl-cert.sh" ]; then
        if [ ! -d "$INSTALL_DIR/scripts" ]; then
            if [ "$IS_ROOT" = true ]; then
                mkdir -p "$INSTALL_DIR/scripts" 2>/dev/null || {
                    log_error "Failed to create scripts directory"
                    exit 1
                }
            else
                sudo mkdir -p "$INSTALL_DIR/scripts" 2>/dev/null || {
                    log_error "Failed to create scripts directory"
                    exit 1
                }
            fi
        fi
        if ! cp "$SCRIPT_DIR/scripts/generate-ssl-cert.sh" "$INSTALL_DIR/scripts/" 2>/dev/null; then
            if [ "$IS_ROOT" = false ]; then
                if ! sudo cp "$SCRIPT_DIR/scripts/generate-ssl-cert.sh" "$INSTALL_DIR/scripts/" 2>/dev/null; then
                    log_error "Failed to copy generate-ssl-cert.sh"
                    exit 1
                fi
            else
                log_error "Failed to copy generate-ssl-cert.sh"
                exit 1
            fi
        fi
        chmod +x "$INSTALL_DIR/scripts/generate-ssl-cert.sh"
        
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
ExecStart=$INSTALL_DIR/scripts/generate-ssl-cert.sh
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
    JOURNALD_CONF_FILE_SOURCE="config/journald-cti-platform.conf"
    JOURNALD_CONF_DIR="/etc/systemd/journald.conf.d"
    
    # Create journald.conf.d directory if it doesn't exist
    if [ "$IS_ROOT" = true ]; then
        mkdir -p "$JOURNALD_CONF_DIR"
    else
        sudo mkdir -p "$JOURNALD_CONF_DIR"
    fi
    
    # Copy journald configuration file
    if [ -f "$SCRIPT_DIR/$JOURNALD_CONF_FILE_SOURCE" ]; then
        if [ "$IS_ROOT" = true ]; then
            if ! cp "$SCRIPT_DIR/$JOURNALD_CONF_FILE_SOURCE" "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" 2>/dev/null; then
                log_warning "Failed to copy journald configuration file"
            elif ! systemctl restart systemd-journald 2>/dev/null; then
                log_warning "Failed to restart systemd-journald. Configuration may not be active."
            else
                log_success "Log rotation configured (max 500MB total, 30 days retention, daily rotation)"
            fi
        else
            if ! sudo cp "$SCRIPT_DIR/$JOURNALD_CONF_FILE_SOURCE" "$JOURNALD_CONF_DIR/$JOURNALD_CONF_FILE" 2>/dev/null; then
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
    if [ ! -f "$SCRIPT_DIR/$SERVICE_FILE_SOURCE" ]; then
        log_error "Service file not found: $SCRIPT_DIR/$SERVICE_FILE_SOURCE"
        log_error "Please ensure the service file is present in the config directory"
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
# POST-INSTALLATION VALIDATION
# ============================================================================

# ============================================================================
# POST-INSTALLATION VALIDATION
# ============================================================================

verify_installation() {
    log_step "Verifying installation..."
    local validation_passed=true
    local validation_errors=()
    local validation_warnings=()
    
    # Test 1: Verify Python is accessible
    if [ -n "$PYTHON_CMD" ] && command -v "$PYTHON_CMD" &>/dev/null; then
        if $PYTHON_CMD --version &>/dev/null; then
            log_info "✓ Python accessible: $PYTHON_CMD"
        else
            validation_errors+=("Python command not functional")
            validation_passed=false
        fi
    else
        validation_errors+=("Python command not found")
        validation_passed=false
    fi
    
    # Test 2: Verify venv exists and is functional
    if [ -d "$INSTALL_DIR/venv" ]; then
        if [ -f "$INSTALL_DIR/venv/bin/python" ]; then
            if "$INSTALL_DIR/venv/bin/python" --version &>/dev/null; then
                log_info "✓ Virtual environment functional"
            else
                validation_errors+=("Venv Python not functional")
                validation_passed=false
            fi
        else
            validation_errors+=("Venv Python executable not found")
            validation_passed=false
        fi
    else
        validation_errors+=("Virtual environment directory not found")
        validation_passed=false
    fi
    
    # Test 3: Verify pip in venv
    if [ -f "$INSTALL_DIR/venv/bin/pip" ]; then
        if "$INSTALL_DIR/venv/bin/pip" --version &>/dev/null; then
            log_info "✓ pip available in venv"
        else
            validation_warnings+=("pip in venv not functional")
        fi
    else
        validation_warnings+=("pip not found in venv")
    fi
    
    # Test 4: Verify critical Python modules can be imported
    local critical_modules=("flask" "werkzeug" "requests")
    for module in "${critical_modules[@]}"; do
        if "$INSTALL_DIR/venv/bin/python" -c "import $module" 2>/dev/null; then
            log_info "✓ Module $module importable"
        else
            validation_errors+=("Critical module $module not importable")
            validation_passed=false
        fi
    done
    
    # Test 5: Verify application directory exists
    if [ -d "$INSTALL_DIR/cti-platform" ]; then
        log_info "✓ Application directory exists"
        
        # Test 5a: Verify app.py exists
        if [ -f "$INSTALL_DIR/cti-platform/app.py" ]; then
            log_info "✓ Application file (app.py) exists"
        else
            validation_errors+=("Application file (app.py) not found")
            validation_passed=false
        fi
        
        # Test 5b: Verify config.py exists
        if [ -f "$INSTALL_DIR/cti-platform/config.py" ]; then
            log_info "✓ Configuration file (config.py) exists"
        else
            validation_warnings+=("Configuration file (config.py) not found")
        fi
    else
        validation_errors+=("Application directory not found")
        validation_passed=false
    fi
    
    # Test 6: Verify service file exists (if systemd available)
    if command -v systemctl &>/dev/null; then
        if [ -f "/etc/systemd/system/$SERVICE_FILE" ]; then
            log_info "✓ Systemd service file exists"
        else
            validation_warnings+=("Systemd service file not found")
        fi
    fi
    
    # Test 7: Verify service user exists
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "✓ Service user exists: $SERVICE_USER"
    else
        validation_warnings+=("Service user not found: $SERVICE_USER")
    fi
    
    # Test 8: Verify permissions on key directories
    local key_dirs=("$INSTALL_DIR/cti-platform" "$INSTALL_DIR/venv")
    for dir in "${key_dirs[@]}"; do
        if [ -d "$dir" ]; then
            if [ -r "$dir" ] && [ -x "$dir" ]; then
                log_info "✓ Directory permissions OK: $dir"
            else
                validation_warnings+=("Directory permissions issue: $dir")
            fi
        fi
    done
    
    # Test 9: Verify network connectivity (if needed for runtime)
    local network_ok=false
    if command -v curl &>/dev/null; then
        if curl -sS --max-time 3 --connect-timeout 2 https://www.python.org &>/dev/null; then
            network_ok=true
        fi
    elif command -v wget &>/dev/null; then
        if wget -q --spider --timeout=3 --tries=1 https://www.python.org &>/dev/null; then
            network_ok=true
        fi
    fi
    
    if [ "$network_ok" = true ]; then
        log_info "✓ Network connectivity available"
    else
        validation_warnings+=("Network connectivity not verified (may affect some features)")
    fi
    
    # Report results
    echo ""
    if [ ${#validation_errors[@]} -gt 0 ]; then
        log_error "Validation errors found:"
        for error in "${validation_errors[@]}"; do
            log_error "  - $error"
        done
    fi
    
    if [ ${#validation_warnings[@]} -gt 0 ]; then
        log_warning "Validation warnings:"
        for warning in "${validation_warnings[@]}"; do
            log_warning "  - $warning"
        done
    fi
    
    if [ "$validation_passed" = true ]; then
        log_success "Installation validation passed"
        return 0
    else
        log_error "Installation validation failed"
        return 1
    fi
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
    download_external_repositories
    configure_log_rotation
    install_service
    start_service
    verify_installation
    
    # Use configured port
    FINAL_PORT="${CTI_PORT:-5001}"
    
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
        log_info "You can generate it later with: $INSTALL_DIR/scripts/generate-ssl-cert.sh"
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
    echo -e "  and resources: iocsearcher, deepdarkCTI,"
    echo -e "  and Ransomware Tool Matrix."
    echo ""
    echo -e "  Odysafe CTI Platform thanks the developers and maintainers"
    echo -e "  of these projects for making their tools and resources"
    echo -e "  available to the community."
    echo ""
}

# Run main function
main

