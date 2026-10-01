#!/bin/sh
# Reviewed official release bytes. No executable remote installer is trusted.
set -eu
if [ "${NOIR_VERSION-1.0.0}" != 1.0.0 ] || [ "${GITLEAKS_VERSION-8.30.1}" != 8.30.1 ] || [ "${TRIVY_VERSION-0.74.0}" != 0.74.0 ]; then
    echo 'Scanner version override requires reviewed filename/digest updates' >&2
    exit 64
fi
case "${1-}" in
  amd64)
    noir=noir_1.0.0_amd64.deb
    noir_sha=e56082a4d74f6507c3118970baa934e13223c55f3e8a336916b68e4d70a19271
    trivy=trivy_0.74.0_Linux-64bit.tar.gz
    trivy_sha=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
    gitleaks=gitleaks_8.30.1_linux_x64.tar.gz
    gitleaks_sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    ;;
  arm64)
    noir=noir_1.0.0_arm64.deb
    noir_sha=e7d28eb56c73b8a3a54f8b6dace1110ff898bddac94876efc59d7f08090f54a0
    trivy=trivy_0.74.0_Linux-ARM64.tar.gz
    trivy_sha=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
    gitleaks=gitleaks_8.30.1_linux_arm64.tar.gz
    gitleaks_sha=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
    ;;
  *) echo 'Unsupported container architecture: require amd64 or arm64' >&2; exit 64 ;;
esac
case "${2-}" in
  --plan)
    printf '%s %s\n' "$noir" "$noir_sha" "$trivy" "$trivy_sha" "$gitleaks" "$gitleaks_sha"
    exit 0 ;;
  '') ;;
  *) echo 'Unsupported installer mode' >&2; exit 64 ;;
esac
owned_dir=$(mktemp -d /tmp/websec-scanners.XXXXXXXX)
cleanup() {
    rm -f "$owned_dir/noir.deb" "$owned_dir/trivy.tgz" "$owned_dir/gitleaks.tgz"
    rmdir "$owned_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
curl -q -fsSL --proto '=https' --retry 3 -o "$owned_dir/noir.deb" "https://github.com/owasp-noir/noir/releases/download/v1.0.0/$noir"
curl -q -fsSL --proto '=https' --retry 3 -o "$owned_dir/trivy.tgz" "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/$trivy"
curl -q -fsSL --proto '=https' --retry 3 -o "$owned_dir/gitleaks.tgz" "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/$gitleaks"
# Verify ALL bytes before any archive extraction or privileged package install.
printf '%s  %s\n' "$noir_sha" "$owned_dir/noir.deb" "$trivy_sha" "$owned_dir/trivy.tgz" "$gitleaks_sha" "$owned_dir/gitleaks.tgz" | sha256sum -c -
tar -xzf "$owned_dir/trivy.tgz" -C /usr/local/bin trivy
tar -xzf "$owned_dir/gitleaks.tgz" -C /usr/local/bin gitleaks
apt-get update
apt-get install -y --no-install-recommends "$owned_dir/noir.deb"
rm -rf /var/lib/apt/lists/*
