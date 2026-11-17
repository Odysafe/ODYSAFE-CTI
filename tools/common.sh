#!/bin/sh

CTI_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ ! -f "$CTI_ROOT/compose.yaml" ]; then
    CTI_ROOT=$(dirname "$CTI_ROOT")
fi

. "$CTI_ROOT/release-images.env"
CTI_STATE_DIR=${CTI_STATE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/odysafe-cti}
case "$CTI_STATE_DIR" in
    /*) ;;
    *) printf '%s\n' 'CTI_STATE_DIR must be an absolute path.' >&2; exit 1 ;;
esac
CTI_UID=$(id -u)
CTI_GID=$(id -g)
export CTI_IMAGE CTI_STATE_DIR CTI_UID CTI_GID

compose() {
    docker compose --project-directory "$CTI_ROOT" -f "$CTI_ROOT/compose.yaml" "$@"
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

prepare_state() {
    umask 077
    mkdir -p "$CTI_STATE_DIR"
    for directory in database uploads outputs zettelforge cache data_shield docs datasets ssl; do
        mkdir -p "$CTI_STATE_DIR/$directory"
    done
}

require_stopped() {
    running=$(compose ps --status running --status restarting -q cti)
    [ -z "$running" ] || fail 'Stop CTI with ./stop before copying its data.'
}
