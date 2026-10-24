#!/bin/sh
# Trusted installer for live repro containers. repro_env.py runs it as root with
# `docker exec -e ... sh <this file>`; every value arrives as an env var, never as code.
#
#   REPRO_FAMILY    debian | rhel | tdnf | suse | alpine
#   REPRO_INSTALL   package (the distro's official Azure CLI package) | pip
#   REPRO_RELEASE   RHEL major release for packages.microsoft.com (rhel family)
#   REPRO_CLI       reported | latest | source | wheels
#   REPRO_CLI_VERSION  exact azure-cli version for reported
#   REPRO_CLI_PATHS    space separated source dirs or wheel files (source | wheels)
#   REPRO_EXT, REPRO_EXT_MODE (add | target), REPRO_EXT_VERSION, REPRO_EXT_PATHS, REPRO_EXT_DIR
#   REPRO_OWNER     uid:gid that owns the mounted workspace and runs the steps
#   REPRO_WORKSPACE mounted workspace to hand back to REPRO_OWNER
#   REPRO_HOME      HOME for the steps
set -eu

log() { printf 'xea-install: %s\n' "$*"; }
retry() {
  n=0
  until "$@"; do
    n=$((n + 1))
    [ "$n" -ge 3 ] && return 1
    sleep 10
  done
}
export PIP_BREAK_SYSTEM_PACKAGES=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
export PIP_ROOT_USER_ACTION=ignore DEBIAN_FRONTEND=noninteractive
PY=""
WANT="${REPRO_CLI_VERSION:-}"
[ "$REPRO_CLI" = reported ] || WANT=""

install_tools() {
  case "$REPRO_FAMILY" in
    debian)
      retry apt-get update -q
      apt-get install -y -q ca-certificates curl gnupg lsb-release bash procps
      ;;
    rhel)
      retry dnf install -y --setopt=install_weak_deps=False ca-certificates bash procps-ng \
        || retry dnf install -y ca-certificates bash
      command -v curl >/dev/null 2>&1 || retry dnf install -y curl
      ;;
    tdnf) retry tdnf install -y ca-certificates bash curl tar ;;
    suse) retry zypper -n install ca-certificates bash curl tar gzip ;;
    alpine) retry apk add --no-cache ca-certificates bash curl ;;
  esac
}

package_cli() {
  case "$REPRO_FAMILY" in
    debian)
      mkdir -p /etc/apt/keyrings
      curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor > /etc/apt/keyrings/microsoft.gpg
      chmod go+r /etc/apt/keyrings/microsoft.gpg
      codename="$(lsb_release -cs)"
      printf 'deb [arch=%s signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ %s main\n' \
        "$(dpkg --print-architecture)" "$codename" > /etc/apt/sources.list.d/azure-cli.list
      retry apt-get update -q
      if [ -n "$WANT" ]; then
        apt-get install -y -q "azure-cli=$WANT-1~$codename"
      else
        apt-get install -y -q azure-cli
      fi
      ;;
    rhel)
      rpm --import https://packages.microsoft.com/keys/microsoft.asc
      if [ "${REPRO_RELEASE:-9}" = 8 ]; then path=8; else path=9.0; fi
      retry dnf install -y "https://packages.microsoft.com/config/rhel/$path/packages-microsoft-prod.rpm"
      if [ -n "$WANT" ]; then retry dnf install -y "azure-cli-$WANT"; else retry dnf install -y azure-cli; fi
      ;;
    tdnf)
      if [ -n "$WANT" ]; then retry tdnf install -y "azure-cli-$WANT"; else retry tdnf install -y azure-cli; fi
      ;;
    suse)
      rpm --import https://packages.microsoft.com/keys/microsoft.asc
      zypper -n addrepo --name 'Azure CLI' --check https://packages.microsoft.com/yumrepos/azure-cli azure-cli
      if [ -n "$WANT" ]; then
        retry zypper -n --gpg-auto-import-keys install --from azure-cli "azure-cli=$WANT"
      else
        retry zypper -n --gpg-auto-import-keys install --from azure-cli azure-cli
      fi
      ;;
    *) log "no package for $REPRO_FAMILY"; return 1 ;;
  esac
  # Use the interpreter the package's az launcher runs, so overlays and extensions land there.
  az_bin="$(command -v az)"
  PY="$(grep -o '/[^ "]*/python3[0-9.]*' "$az_bin" | head -n 1 || true)"
  [ -n "$PY" ] || PY="$(command -v python3)"
  "$PY" -m pip --version >/dev/null 2>&1 || "$PY" -m ensurepip >/dev/null 2>&1 || true
}

pip_python() {
  case "$REPRO_FAMILY" in
    debian)
      apt-get install -y -q python3 python3-pip python3-venv python3-dev gcc libffi-dev libssl-dev
      PY=python3
      ;;
    rhel)
      for v in 3.12 3.11; do
        if dnf install -y "python$v" "python$v-pip" "python$v-devel" gcc libffi-devel >/dev/null 2>&1; then
          PY="python$v"
          break
        fi
      done
      if [ -z "$PY" ]; then
        retry dnf install -y python3 python3-pip python3-devel gcc libffi-devel
        PY=python3
      fi
      ;;
    tdnf)
      retry tdnf install -y python3 python3-pip python3-devel gcc glibc-devel binutils kernel-headers libffi-devel
      PY=python3
      ;;
    suse)
      if zypper -n install python311 python311-pip python311-devel gcc libffi-devel >/dev/null 2>&1; then
        PY=python3.11
      else
        retry zypper -n install python3 python3-pip python3-devel gcc libffi-devel
        PY=python3
      fi
      ;;
    alpine)
      retry apk add --no-cache python3 py3-pip python3-dev gcc musl-dev libffi-dev openssl-dev \
        cargo make linux-headers
      PY=python3
      ;;
  esac
  "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
}

pip_install() {
  # shellcheck disable=SC2086 # REPRO_*_PATHS are space separated absolute paths
  "$PY" -m pip install "$@"
}

install_tools
case "$REPRO_INSTALL" in
  package)
    package_cli
    case "$REPRO_CLI" in
      # dev and PR heads overlay the packaged CLI, so they run on the package's own Python.
      source|wheels) pip_install $REPRO_CLI_PATHS ;;
    esac
    ;;
  pip)
    pip_python
    case "$REPRO_CLI" in
      reported) pip_install "azure-cli==$WANT" ;;
      latest) pip_install azure-cli ;;
      source|wheels) pip_install $REPRO_CLI_PATHS ;;
    esac
    hash -r 2>/dev/null || true
    ;;
esac

AZ="$(command -v az)"
if [ -n "${REPRO_EXT:-}" ]; then
  mkdir -p "$REPRO_EXT_DIR"
  if [ "$REPRO_EXT_MODE" = target ]; then
    pip_install --target "$REPRO_EXT_DIR/$REPRO_EXT" $REPRO_EXT_PATHS
  elif [ -n "${REPRO_EXT_VERSION:-}" ]; then
    AZURE_EXTENSION_DIR="$REPRO_EXT_DIR" "$AZ" extension add --name "$REPRO_EXT" \
      --version "$REPRO_EXT_VERSION" --yes
  else
    AZURE_EXTENSION_DIR="$REPRO_EXT_DIR" "$AZ" extension add --name "$REPRO_EXT" --yes
  fi
fi

mkdir -p "$REPRO_HOME"
chown -R "$REPRO_OWNER" "$REPRO_HOME" "$REPRO_WORKSPACE"
printf 'XEA_AZ=%s\n' "$AZ"
