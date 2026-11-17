#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

[ "$#" -le 1 ] || fail 'Usage: ./tools/prepare-memory.sh [--offline]'
case "${1:-}" in
    ''|--offline) ;;
    *) fail 'Usage: ./tools/prepare-memory.sh [--offline]' ;;
esac

docker run --rm --pull never --network=none \
    --user "$CTI_UID:$CTI_GID" --workdir /tmp \
    --env HF_HUB_OFFLINE=1 --env HF_HUB_DISABLE_TELEMETRY=1 \
    --env FASTEMBED_CACHE_PATH=/opt/cti-bundle/model-cache --env HF_HOME=/tmp/cti-hf \
    --env ZETTELFORGE_DATA_DIR=/tmp/cti-memory --env AMEM_DATA_DIR=/tmp/cti-memory \
    --entrypoint python "$CTI_IMAGE" -c '
from zettelforge.vector_memory import get_embedding

embedding = get_embedding("ODYSAFE CTI offline memory verification")
if embedding is None or len(embedding) == 0 or not any(embedding):
    raise SystemExit("No usable embedding was produced")
print(f"Embedding ready ({len(embedding)} dimensions)")
'
