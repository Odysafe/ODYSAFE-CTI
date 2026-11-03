#!/bin/bash

set -euo pipefail

SERVICE_NAME="odysafe-cti"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${CTI_INSTALL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

SYSTEMD_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INITD_SERVICE_FILE="/etc/init.d/${SERVICE_NAME}"
ENV_FILE="/etc/${SERVICE_NAME}.env"

ACTION="${1:-install}"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    SERVICE_USER="$SUDO_USER"
else
    SERVICE_USER="${USER:-$(id -un)}"
fi

SERVICE_GROUP="$(id -gn "$SERVICE_USER")"

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

check_application() {
    if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
        echo "Error: Python virtual environment not found:"
        echo "  $INSTALL_DIR/venv/bin/python"
        echo
        echo "Run ./install.sh first."
        exit 1
    fi

    if [ ! -f "$INSTALL_DIR/cti-platform/app.py" ]; then
        echo "Error: application not found:"
        echo "  $INSTALL_DIR/cti-platform/app.py"
        exit 1
    fi
}

has_systemd() {
    command -v systemctl >/dev/null 2>&1 \
        && [ -d /run/systemd/system ] \
        && [ "$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')" = "systemd" ]
}

create_env_file() {
    local secret_key ssl_enabled env_tmp

    secret_key="$(openssl rand -hex 32)"
    ssl_enabled="false"

    if [ -f "$INSTALL_DIR/cti-platform/ssl/cert.pem" ] \
        && [ -f "$INSTALL_DIR/cti-platform/ssl/key.pem" ]; then
        ssl_enabled="true"
    fi

    if run_as_root test -f "$ENV_FILE"; then
        return 0
    fi

    env_tmp="$(mktemp)"

    {
        printf 'CTI_SECRET_KEY=%s\n' "$secret_key"
        printf 'CTI_PORT=%s\n' "${CTI_PORT:-5001}"
        printf 'CTI_USE_SSL=%s\n' "${CTI_USE_SSL:-$ssl_enabled}"
        printf 'PYTHONUNBUFFERED=1\n'
    } > "$env_tmp"

    run_as_root install -m 600 "$env_tmp" "$ENV_FILE"
    rm -f "$env_tmp"
}

install_systemd_service() {
    local tmp

    tmp="$(mktemp)"

    cat > "$tmp" <<EOF
[Unit]
Description=ODYSAFE Cyber Threat Intelligence Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR/cti-platform
EnvironmentFile=-$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/cti-platform/app.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

    run_as_root install -m 644 "$tmp" "$SYSTEMD_SERVICE_FILE"
    rm -f "$tmp"

    run_as_root systemctl daemon-reload
    run_as_root systemctl enable --now "$SERVICE_NAME"

    echo
    echo "ODYSAFE installed as systemd service."
    echo "Status : systemctl status $SERVICE_NAME"
    echo "Logs   : journalctl -u $SERVICE_NAME -f"
}

install_initd_service() {
    local tmp

    tmp="$(mktemp)"

    cat > "$tmp" <<EOF
#!/bin/sh

### BEGIN INIT INFO
# Provides:          $SERVICE_NAME
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ODYSAFE CTI Platform
### END INIT INFO

NAME="$SERVICE_NAME"
BASE="$INSTALL_DIR"
APP="\$BASE/cti-platform/app.py"
PYTHON="\$BASE/venv/bin/python"
PIDFILE="/var/run/\$NAME.pid"
LOGFILE="/var/log/\$NAME.log"
ENVFILE="$ENV_FILE"

load_env() {
    if [ -f "\$ENVFILE" ]; then
        set -a
        . "\$ENVFILE"
        set +a
    fi
}

start_service() {
    if [ -f "\$PIDFILE" ] && kill -0 "\$(cat "\$PIDFILE")" 2>/dev/null; then
        echo "\$NAME already running (PID \$(cat "\$PIDFILE"))"
        return 0
    fi

    if [ ! -x "\$PYTHON" ]; then
        echo "Error: Python venv not found: \$PYTHON"
        return 1
    fi

    if [ ! -f "\$APP" ]; then
        echo "Error: application not found: \$APP"
        return 1
    fi

    load_env

    cd "\$BASE/cti-platform" || return 1

    echo "Starting \$NAME..."

    nohup "\$PYTHON" "\$APP" >>"\$LOGFILE" 2>&1 &
    echo \$! > "\$PIDFILE"

    sleep 2

    if kill -0 "\$(cat "\$PIDFILE")" 2>/dev/null; then
        echo "\$NAME started (PID \$(cat "\$PIDFILE"))"
        return 0
    fi

    echo "Failed to start \$NAME"
    rm -f "\$PIDFILE"
    tail -n 30 "\$LOGFILE" 2>/dev/null || true
    return 1
}

stop_service() {
    if [ ! -f "\$PIDFILE" ]; then
        echo "\$NAME is not running"
        return 0
    fi

    PID="\$(cat "\$PIDFILE")"

    if kill -0 "\$PID" 2>/dev/null; then
        echo "Stopping \$NAME..."
        kill "\$PID"

        i=0
        while kill -0 "\$PID" 2>/dev/null && [ "\$i" -lt 15 ]; do
            sleep 1
            i=\$((i + 1))
        done

        if kill -0 "\$PID" 2>/dev/null; then
            kill -9 "\$PID"
        fi
    fi

    rm -f "\$PIDFILE"
    echo "\$NAME stopped"
}

status_service() {
    if [ -f "\$PIDFILE" ]; then
        PID="\$(cat "\$PIDFILE")"

        if kill -0 "\$PID" 2>/dev/null; then
            echo "\$NAME is running (PID \$PID)"
            return 0
        fi

        rm -f "\$PIDFILE"
    fi

    echo "\$NAME is not running"
    return 3
}

case "\${1:-}" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        stop_service
        sleep 1
        start_service
        ;;
    status)
        status_service
        ;;
    logs)
        touch "\$LOGFILE"
        tail -f "\$LOGFILE"
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF

    run_as_root install -m 755 "$tmp" "$INITD_SERVICE_FILE"
    rm -f "$tmp"

    rm -f "/var/run/${SERVICE_NAME}.pid" 2>/dev/null || true

    run_as_root service "$SERVICE_NAME" start

    echo
    echo "ODYSAFE installed as SysV service."
    echo "Status : service $SERVICE_NAME status"
    echo "Restart: service $SERVICE_NAME restart"
    echo "Stop   : service $SERVICE_NAME stop"
    echo "Logs   : tail -f /var/log/${SERVICE_NAME}.log"
}

install_service() {
    check_application
    create_env_file

    echo "ODYSAFE install directory:"
    echo "  $INSTALL_DIR"
    echo

    if has_systemd; then
        echo "systemd detected."
        install_systemd_service
    else
        echo "systemd unavailable/container detected."
        echo "Installing SysV service instead."
        install_initd_service
    fi
}

remove_service() {
    if has_systemd && run_as_root test -f "$SYSTEMD_SERVICE_FILE"; then
        run_as_root systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
        run_as_root rm -f "$SYSTEMD_SERVICE_FILE"
        run_as_root systemctl daemon-reload
    fi

    if run_as_root test -f "$INITD_SERVICE_FILE"; then
        run_as_root service "$SERVICE_NAME" stop 2>/dev/null || true
        run_as_root rm -f "$INITD_SERVICE_FILE"
    fi

    echo "ODYSAFE service removed."
    echo "Environment file preserved: $ENV_FILE"
}

service_status() {
    if has_systemd && run_as_root test -f "$SYSTEMD_SERVICE_FILE"; then
        run_as_root systemctl status "$SERVICE_NAME"
    elif run_as_root test -f "$INITD_SERVICE_FILE"; then
        run_as_root service "$SERVICE_NAME" status
    else
        echo "ODYSAFE service is not installed."
        exit 1
    fi
}

service_restart() {
    if has_systemd && run_as_root test -f "$SYSTEMD_SERVICE_FILE"; then
        run_as_root systemctl restart "$SERVICE_NAME"
        run_as_root systemctl status "$SERVICE_NAME" --no-pager
    elif run_as_root test -f "$INITD_SERVICE_FILE"; then
        run_as_root service "$SERVICE_NAME" restart
        run_as_root service "$SERVICE_NAME" status
    else
        echo "ODYSAFE service is not installed."
        exit 1
    fi
}

service_logs() {
    if has_systemd && run_as_root test -f "$SYSTEMD_SERVICE_FILE"; then
        run_as_root journalctl -u "$SERVICE_NAME" -f
    elif run_as_root test -f "$INITD_SERVICE_FILE"; then
        run_as_root tail -f "/var/log/${SERVICE_NAME}.log"
    else
        echo "ODYSAFE service is not installed."
        exit 1
    fi
}

case "$ACTION" in
    install)
        install_service
        ;;
    remove)
        remove_service
        ;;
    status)
        service_status
        ;;
    restart)
        service_restart
        ;;
    logs)
        service_logs
        ;;
    *)
        echo "Usage: $0 {install|remove|status|restart|logs}" >&2
        exit 2
        ;;
esac
