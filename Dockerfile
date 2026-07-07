# websec-validator — bundles the tool + every scanner it orchestrates so it runs
# reproducibly on any machine (no "install 5 tools" friction). Debian/glibc base
# keeps Semgrep happy; OWASP Noir installs from its official .deb. Arch-aware via
# Docker's TARGETARCH (amd64 / arm64).
#
#   docker build -t websec-validator .
#   docker run --rm -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
FROM python:3.14-slim

# TARGETARCH is auto-populated by BuildKit (arm64/amd64) — do NOT give it a
# default, or it shadows the real build arch and pulls the wrong-arch packages.
ARG TARGETARCH
ARG NOIR_VERSION=1.1.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.59.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# OWASP Noir (route engine) — official .deb for the target arch, deps via apt
RUN curl -fsSL -o /tmp/noir.deb \
      "https://github.com/owasp-noir/noir/releases/download/v${NOIR_VERSION}/noir_${NOIR_VERSION}_${TARGETARCH}.deb" \
    && apt-get update && apt-get install -y --no-install-recommends /tmp/noir.deb \
    && rm /tmp/noir.deb && rm -rf /var/lib/apt/lists/*

# Trivy (SCA / secrets / IaC) — pin the installer to a TAGGED ref (not the mutable `main`
# branch, which is a curl|sh-to-root supply-chain risk) and pin the version (install.sh takes
# the tag as a trailing arg; it auto-detects arch). Bump TRIVY_VERSION + re-run `docker build`.
RUN curl -sfL "https://raw.githubusercontent.com/aquasecurity/trivy/v${TRIVY_VERSION}/contrib/install.sh" \
      | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

# Gitleaks (secrets)
RUN case "${TARGETARCH}" in amd64) GL=x64 ;; arm64) GL=arm64 ;; *) GL="${TARGETARCH}" ;; esac \
    && curl -fsSL -o /tmp/gl.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz" \
    && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks && rm /tmp/gl.tgz

# Semgrep (SAST) + Checkov (IaC)
RUN pip install --no-cache-dir semgrep==1.168.0 checkov==3.3.6

# The tool
WORKDIR /opt/websec
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Run as a non-root user (hardening — the tool only needs to read code + write its
# report). Pass `--user "$(id -u):$(id -g)"` at runtime so output written to a
# mounted volume matches your host user.
RUN useradd --create-home --uid 1001 websec
WORKDIR /scan
USER websec
ENTRYPOINT ["websec"]
CMD ["--help"]
