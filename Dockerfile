# Default bundles optional scanners; --target core selects only the stdlib engine.
# Pins bind reviewed base/archive bytes, not apt or all transitive dependencies.
FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d AS core

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/websec
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 1001 websec
WORKDIR /scan
USER websec
HEALTHCHECK NONE
ENTRYPOINT ["websec"]
CMD ["--help"]

FROM core AS bundled
USER root

# TARGETARCH is auto-populated by BuildKit (arm64/amd64) — do NOT give it a
# default, or it shadows the real build arch and pulls the wrong-arch packages.
ARG TARGETARCH
ARG NOIR_VERSION=1.0.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG SEMGREP_VERSION=1.178.0
ARG CHECKOV_VERSION=3.3.21

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/install-container-scanners.sh /opt/websec/install-container-scanners.sh
RUN NOIR_VERSION="${NOIR_VERSION}" GITLEAKS_VERSION="${GITLEAKS_VERSION}" TRIVY_VERSION="${TRIVY_VERSION}" \
      sh /opt/websec/install-container-scanners.sh "${TARGETARCH}"
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "checkov==${CHECKOV_VERSION}"
USER websec
