#!/usr/bin/env bash

# ============================================================================
# ODYSAFE CTI Platform · Docker Linux installer
# Builds a self-contained Linux container image with ODYSAFE installed,
# third-party CTI data preloaded, HTTPS enabled, and the app supervised at boot.
# ============================================================================

set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-odysafe-cti:local}"
CONTAINER_NAME="${CONTAINER_NAME:-odysafe-cti}"
HOST_PORT="${HOST_PORT:-5001}"
CONTAINER_PORT="${CONTAINER_PORT:-5001}"
BASE_IMAGE="${BASE_IMAGE:-debian:12-slim}"
RUN_AFTER_BUILD="${RUN_AFTER_BUILD:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/odysafe-docker.XXXXXX")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() {
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

log() {
    printf "${CYAN}[ODYSAFE Docker]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

section() {
    printf "\n${MAGENTA}${BOLD}================================================================${NC}\n"
    printf "${WHITE}${BOLD}  %s${NC}\n" "$1"
    printf "${MAGENTA}${BOLD}================================================================${NC}\n"
}

step() {
    printf "\n${BLUE}${BOLD}▶ %s${NC}\n" "$1"
}

show_banner() {
    printf "\n${MAGENTA}${BOLD}"
    printf "  ██████╗ ██████╗ ██╗   ██╗███████╗ █████╗ ███████╗███████╗\n"
    printf " ██╔═══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝\n"
    printf " ██║   ██║██║  ██║ ╚████╔╝ ███████╗███████║█████╗  █████╗  \n"
    printf " ██║   ██║██║  ██║  ╚██╔╝  ╚════██║██╔══██║██╔══╝  ██╔══╝  \n"
    printf " ╚██████╔╝██████╔╝   ██║   ███████║██║  ██║██║     ███████╗\n"
    printf "  ╚═════╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝\n"
    printf "${NC}"
    printf "${CYAN}${BOLD}  Docker Linux installer${NC}\n\n"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$1" >&2
        exit 1
    fi
}

require_cmd docker
require_cmd rsync

show_banner

if [ ! -f "$REPO_ROOT/install.sh" ] || [ ! -d "$REPO_ROOT/cti-platform" ]; then
    printf 'This script must be located in the ODYSAFE-CTI/scripts directory.\n' >&2
    printf 'Detected repository root: %s\n' "$REPO_ROOT" >&2
    exit 1
fi

section "1/4 - Prepare Docker Build Context"
log "Using repository root: $REPO_ROOT"
log "Preparing Docker build context from the current ODYSAFE-CTI repository."
log "Runtime data is excluded from the image: local database, uploads, outputs, cache, and venv."
rsync -a \
    --exclude '.git' \
    --exclude 'venv' \
    --exclude 'cti-platform/database' \
    --exclude 'cti-platform/uploads' \
    --exclude 'cti-platform/outputs' \
    --exclude 'cti-platform/data/zettelforge' \
    --exclude 'cti-platform/modules/cache' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "$REPO_ROOT/" "$BUILD_DIR/ODYSAFE-CTI/"
success "Docker build context prepared."

step "Writing supervisord service configuration."
mkdir -p "$BUILD_DIR/docker"
cat > "$BUILD_DIR/docker/odysafe-supervisor.conf" <<SUPERVISOR
[program:odysafe-cti]
directory=/opt/odysafe/ODYSAFE-CTI/cti-platform
command=/opt/odysafe/ODYSAFE-CTI/venv/bin/python /opt/odysafe/ODYSAFE-CTI/cti-platform/app.py
environment=CTI_INSTALL_DIR="/opt/odysafe/ODYSAFE-CTI",CTI_PORT="${CONTAINER_PORT}",CTI_USE_SSL="true",PYTHONUNBUFFERED="1"
autostart=true
autorestart=true
startsecs=5
stopsignal=TERM
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0
SUPERVISOR
success "Supervised ODYSAFE service configuration generated."

section "2/4 - Generate Dockerfile"
cat > "$BUILD_DIR/Dockerfile" <<DOCKERFILE
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV CTI_INSTALL_DIR=/opt/odysafe/ODYSAFE-CTI
ENV CTI_PORT=${CONTAINER_PORT}
ENV CTI_USE_SSL=true
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm

RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        bash \\
        ca-certificates \\
        curl \\
        git \\
        iproute2 \\
        libmagic1 \\
        openssl \\
        python3 \\
        python3-pip \\
        python3-venv \\
        rsync \\
        supervisor \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/odysafe
COPY ODYSAFE-CTI /opt/odysafe/ODYSAFE-CTI

RUN chmod +x /opt/odysafe/ODYSAFE-CTI/install.sh \\
    /opt/odysafe/ODYSAFE-CTI/start.sh \\
    /opt/odysafe/ODYSAFE-CTI/scripts/generate-ssl-cert.sh \\
    && cd /opt/odysafe/ODYSAFE-CTI \\
    && printf '\\n\\n' | ./install.sh \\
    && ./scripts/generate-ssl-cert.sh \\
    && mkdir -p /var/log/supervisor

COPY docker/odysafe-supervisor.conf /etc/supervisor/conf.d/odysafe.conf

EXPOSE ${CONTAINER_PORT}

HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=5 \\
    CMD curl -kfsS "https://127.0.0.1:${CONTAINER_PORT}/" >/dev/null || exit 1

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
DOCKERFILE

success "Dockerfile generated for ${BASE_IMAGE}."
log "The image will install ODYSAFE dependencies, preload pinned CTI repositories, generate HTTPS certificates, and configure supervisord."

section "3/4 - Build Docker Image"
log "Building image: ${IMAGE_NAME}"
docker build -t "$IMAGE_NAME" "$BUILD_DIR"

success "Image built successfully: ${IMAGE_NAME}"

if [ "$RUN_AFTER_BUILD" = "1" ]; then
    section "4/4 - Start ODYSAFE Container"
    if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
        warn "Existing container found. Removing: ${CONTAINER_NAME}"
        docker rm -f "$CONTAINER_NAME" >/dev/null
        success "Previous container removed."
    fi

    log "Starting container: ${CONTAINER_NAME}"
    log "Docker will publish host port ${HOST_PORT} to container port ${CONTAINER_PORT}."
    docker run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        -p "${HOST_PORT}:${CONTAINER_PORT}" \
        "$IMAGE_NAME" >/dev/null

    success "ODYSAFE CTI is starting as a supervised service inside the container."
    printf "\n${GREEN}${BOLD}Ready.${NC}\n"
    printf "${WHITE}Open:${NC} ${CYAN}${BOLD}https://localhost:${HOST_PORT}${NC}\n"
    printf "${WHITE}Logs:${NC} ${CYAN}docker logs -f ${CONTAINER_NAME}${NC}\n\n"
else
    section "4/4 - Container Start Skipped"
    warn "RUN_AFTER_BUILD=0, container not started."
    log "Start later with:"
    printf "${CYAN}docker run -d --name ${CONTAINER_NAME} --restart unless-stopped -p ${HOST_PORT}:${CONTAINER_PORT} ${IMAGE_NAME}${NC}\n"
fi
