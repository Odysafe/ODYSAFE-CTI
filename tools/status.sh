#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"
compose ps -a
