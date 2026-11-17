#!/bin/sh
set -eu
umask 077

if [ ! -s ssl/session.key ]; then
    temporary=$(mktemp ssl/session.XXXXXX)
    openssl rand -hex 32 > "$temporary"
    mv "$temporary" ssl/session.key
fi
if [ "${CTI_USE_SSL:-true}" = true ] && { [ ! -s ssl/key.pem ] || [ ! -s ssl/cert.pem ] ||
    ! openssl x509 -checkend 86400 -noout -in ssl/cert.pem >/dev/null; }; then
    temporary=$(mktemp -d ssl/tls.XXXXXX)
    trap 'rm -rf "$temporary"' EXIT
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
        -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
        -keyout "$temporary/key.pem" -out "$temporary/cert.pem" 2>/dev/null
    mv "$temporary/key.pem" "$temporary/cert.pem" ssl/
    rmdir "$temporary"
    trap - EXIT
fi
CTI_SECRET_KEY=$(cat ssl/session.key)
export CTI_SECRET_KEY

set --
if [ "${CTI_USE_SSL:-true}" = true ]; then
    set -- --certfile ssl/cert.pem --keyfile ssl/key.pem
fi
exec gunicorn --bind "0.0.0.0:${CTI_PORT:-5001}" --workers 1 --threads "${CTI_WEB_THREADS:-4}" \
    --timeout 180 "$@" app:app
