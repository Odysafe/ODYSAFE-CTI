#!/bin/bash

# ============================================================================
# SSL Certificate Generation Script for Odysafe CTI Platform
# Generates self-signed certificate valid for 1 year
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
INSTALL_DIR="/opt/odysafe-cti-platform"
SSL_DIR="$INSTALL_DIR/cti-platform/ssl"
CERT_FILE="$SSL_DIR/cert.pem"
KEY_FILE="$SSL_DIR/key.pem"

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
if [ "$EUID" -ne 0 ]; then 
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

# Create SSL directory
mkdir -p "$SSL_DIR"

# Get hostname or IP
HOSTNAME=$(hostname -f 2>/dev/null || hostname || echo "localhost")
IP_ADDRESS=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.0.1")

log_info "Generating self-signed SSL certificate..."
log_info "Hostname: $HOSTNAME"
log_info "IP Address: $IP_ADDRESS"
log_info "Valid for: 1 year"

# Generate certificate
openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 365 -nodes \
    -subj "/C=FR/ST=France/L=Paris/O=Odysafe/OU=CTI Platform/CN=$HOSTNAME" \
    -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:$IP_ADDRESS,IP:127.0.0.1" \
    2>/dev/null

if [ $? -eq 0 ] && [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    # Set permissions
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    chown odysafe-cti-platform:odysafe-cti-platform "$CERT_FILE" "$KEY_FILE"
    
    log_success "SSL certificate generated successfully"
    log_info "Certificate: $CERT_FILE"
    log_info "Private key: $KEY_FILE"
    log_info "Valid until: $(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)"
    echo ""
    log_info "To use your own certificate, replace:"
    log_info "  - $CERT_FILE (your certificate)"
    log_info "  - $KEY_FILE (your private key)"
    log_info "Then restart the service: systemctl restart odysafe-cti-platform"
else
    log_error "Failed to generate SSL certificate"
    exit 1
fi

