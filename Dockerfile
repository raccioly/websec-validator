# websec-validator — bundles the tool + every scanner it orchestrates so it runs
# reproducibly on any machine (no "install 5 tools" friction). Debian/glibc base
# keeps Semgrep happy; OWASP Noir installs from its official .deb. Arch-aware via
# Docker's TARGETARCH (amd64 / arm64).
#
#   docker build -t websec-validator .
#   docker run --rm -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
FROM python:3.12-slim

# TARGETARCH is auto-populated by BuildKit (arm64/amd64) — do NOT give it a
# default, or it shadows the real build arch and pulls the wrong-arch packages.
ARG TARGETARCH
ARG NOIR_VERSION=1.0.0
ARG GITLEAKS_VERSION=8.30.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# OWASP Noir (route engine) — official .deb for the target arch, deps via apt
RUN curl -fsSL -o /tmp/noir.deb \
      "https://github.com/owasp-noir/noir/releases/download/v${NOIR_VERSION}/noir_${NOIR_VERSION}_${TARGETARCH}.deb" \
    && apt-get update && apt-get install -y --no-install-recommends /tmp/noir.deb \
    && rm /tmp/noir.deb && rm -rf /var/lib/apt/lists/*

# Trivy (SCA / secrets / IaC) — install script auto-detects arch
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# Gitleaks (secrets)
RUN case "${TARGETARCH}" in amd64) GL=x64 ;; arm64) GL=arm64 ;; *) GL="${TARGETARCH}" ;; esac \
    && curl -fsSL -o /tmp/gl.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz" \
    && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks && rm /tmp/gl.tgz

# Semgrep (SAST) + Checkov (IaC)
RUN pip install --no-cache-dir semgrep checkov

# The tool
WORKDIR /opt/websec
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

WORKDIR /scan
ENTRYPOINT ["websec"]
CMD ["--help"]
