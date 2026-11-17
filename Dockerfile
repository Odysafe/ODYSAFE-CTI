# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS bundled-model
ADD --checksum=sha256:8b29669bf6d1608c846b4c0fb08876fa8d1f99e6c7c72106fb550c8f68bee382 https://github.com/Odysafe/ODYSAFE-CTI/releases/download/v1.0.9/odysafe-cti-data-1.0.1.tar.gz /tmp/data-pack.tar.gz
RUN mkdir /opt/cti-bundle \
    && tar -xzf /tmp/data-pack.tar.gz -C /opt/cti-bundle --strip-components=1 \
        odysafe-cti-data/model-cache odysafe-cti-data/licenses/Apache-2.0.txt \
        odysafe-cti-data/licenses/nomic-model-card.md \
    && chmod -R a+rX /opt/cti-bundle

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git libmagic1 openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/odysafe/ODYSAFE-CTI
COPY scripts/requirements.lock scripts/requirements.lock
RUN python -m pip install --no-cache-dir -r scripts/requirements.lock gunicorn==23.0.0 \
    && python -m pip check
COPY --from=bundled-model /opt/cti-bundle /opt/cti-bundle
COPY scripts/pinned_sources.json scripts/pinned_sources.json
COPY cti-platform/ cti-platform/
COPY docker/entrypoint.sh /usr/local/bin/cti-entrypoint

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
WORKDIR /opt/odysafe/ODYSAFE-CTI/cti-platform
ENTRYPOINT ["/bin/sh", "/usr/local/bin/cti-entrypoint"]
