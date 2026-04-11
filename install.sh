#!/usr/bin/env sh
# CascadeGuard — One-shot install and scan
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/cascadeguard/cascadeguard/main/install.sh | sh
#   curl -sSL https://get.cascadeguard.com | sh
#
# Options:
#   --no-install       Don't install permanently (temp venv, cleaned up after)
#   --no-scan          Install only, don't scan
#   --yes, -y          Skip confirmation prompt (use defaults)
#   --dir PATH         Directory to scan (default: current directory)
#   --non-interactive  Scan all artifacts without prompting
#   --format FORMAT    Output format: text, json (default: text)
#   --output FILE      Write results to file instead of stdout
#
# Examples:
#   curl -sSL https://get.cascadeguard.com | sh
#   curl -sSL https://get.cascadeguard.com | sh -s -- --no-scan
#   curl -sSL https://get.cascadeguard.com | sh -s -- --no-install
#   curl -sSL https://get.cascadeguard.com | sh -s -- --yes --format json

set -eu

CASCADEGUARD_REPO="${CASCADEGUARD_REPO:-https://github.com/cascadeguard/cascadeguard.git}"
CASCADEGUARD_BRANCH="${CASCADEGUARD_BRANCH:-main}"
CASCADEGUARD_HOME="${CASCADEGUARD_HOME:-${HOME}/.cascadeguard}"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11

# ---------------------------------------------------------------------------
# Colours (disabled when not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

info()  { printf "${CYAN}▸${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}✔${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET} %s\n" "$*" >&2; }
error() { printf "${RED}✖${RESET} %s\n" "$*" >&2; }
die()   { error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
DO_INSTALL=1
DO_SCAN=1
AUTO_YES=0
SCAN_ARGS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --no-install) DO_INSTALL=0; shift ;;
    --no-scan)    DO_SCAN=0; shift ;;
    --yes|-y)     AUTO_YES=1; shift ;;
    *)            SCAN_ARGS="${SCAN_ARGS} $1"; shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
detect_platform() {
  OS="$(uname -s)"; ARCH="$(uname -m)"
  case "$OS" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="darwin" ;;
    *)       die "Unsupported OS: $OS" ;;
  esac
  case "$ARCH" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             die "Unsupported architecture: $ARCH" ;;
  esac
}

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
PYTHON="" PYTHON_VERSION="" GIT_VERSION="" DOCKER_VERSION="" DOCKER_RUNNING=""

check_python() {
  for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
      version=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || continue
      major=$(echo "$version" | cut -d. -f1)
      minor=$(echo "$version" | cut -d. -f2)
      if [ "$major" -ge "$MIN_PYTHON_MAJOR" ] && [ "$minor" -ge "$MIN_PYTHON_MINOR" ]; then
        PYTHON="$cmd"
        PYTHON_VERSION="$($cmd --version 2>&1)"
        return 0
      fi
    fi
  done
  return 1
}

check_git() {
  if command -v git >/dev/null 2>&1; then
    GIT_VERSION="$(git --version 2>&1)"
  fi
}

check_docker() {
  if command -v docker >/dev/null 2>&1; then
    DOCKER_VERSION="$(docker --version 2>&1)"
    if docker info >/dev/null 2>&1; then
      DOCKER_RUNNING="running"
    else
      DOCKER_RUNNING="installed but not running"
    fi
  fi
}

print_environment() {
  printf "\n"
  printf "  ${BOLD}Environment${RESET}\n"
  printf "  ──────────────────────────────────────\n"
  printf "  Platform     ${BOLD}${OS}/${ARCH}${RESET}\n"

  if [ -n "$PYTHON_VERSION" ]; then
    printf "  Python       ${GREEN}${PYTHON_VERSION}${RESET}\n"
  else
    printf "  Python       ${RED}not found (3.11+ required)${RESET}\n"
  fi

  if [ -n "$GIT_VERSION" ]; then
    printf "  Git          ${GREEN}${GIT_VERSION}${RESET}\n"
  else
    printf "  Git          ${DIM}not found${RESET}\n"
  fi

  if [ -n "$DOCKER_VERSION" ]; then
    if [ "$DOCKER_RUNNING" = "running" ]; then
      printf "  Docker       ${GREEN}${DOCKER_VERSION} (${DOCKER_RUNNING})${RESET}\n"
    else
      printf "  Docker       ${YELLOW}${DOCKER_VERSION} (${DOCKER_RUNNING})${RESET}\n"
    fi
  else
    printf "  Docker       ${DIM}not found${RESET}\n"
  fi

  printf "  ──────────────────────────────────────\n"

  if [ "$CASCADEGUARD_BRANCH" != "main" ]; then
    printf "  Branch       ${YELLOW}${CASCADEGUARD_BRANCH}${RESET} ${DIM}(non-default)${RESET}\n"
    printf "  ──────────────────────────────────────\n"
  fi

  printf "\n"
}

# ---------------------------------------------------------------------------
# Find a writable directory on PATH for symlinking
# ---------------------------------------------------------------------------
LINK_DIR=""

find_link_dir() {
  if command -v cascadeguard >/dev/null 2>&1; then
    EXISTING="$(command -v cascadeguard)"
    if [ -L "$EXISTING" ]; then
      LINK_DIR="$(dirname "$EXISTING")"
      return 0
    fi
    LINK_DIR=""
    return 0
  fi

  for candidate in \
    "${HOME}/.local/bin" \
    "${HOME}/bin" \
    "/usr/local/bin" \
  ; do
    case ":${PATH}:" in
      *":${candidate}:"*) ;;
      *) continue ;;
    esac
    if [ "$candidate" = "${HOME}/.local/bin" ] || [ "$candidate" = "${HOME}/bin" ]; then
      mkdir -p "$candidate" 2>/dev/null || continue
    fi
    if [ -d "$candidate" ] && [ -w "$candidate" ]; then
      LINK_DIR="$candidate"
      return 0
    fi
  done

  LINK_DIR=""
  return 1
}

# ---------------------------------------------------------------------------
# Interactive confirmation with toggleable options
# ---------------------------------------------------------------------------
confirm_proceed() {
  if [ "$AUTO_YES" -eq 1 ]; then
    return 0
  fi

  # Piped stdin — no way to prompt, proceed automatically
  if [ ! -t 0 ]; then
    info "Non-interactive mode detected, proceeding automatically"
    return 0
  fi

  # Show the plan
  _print_plan

  printf "  ${BOLD}Proceed? [Y/n/c]${RESET}  ${DIM}(c = configure)${RESET} "
  read -r answer </dev/tty

  case "$answer" in
    [nN]*)
      printf "\n"
      info "Cancelled."
      exit 0
      ;;
    [cC]*)
      _configure_options
      ;;
    *)
      printf "\n"
      ;;
  esac
}

_print_plan() {
  STEP=1
  printf "  This will:\n"

  if [ "$DO_INSTALL" -eq 1 ]; then
    printf "    ${STEP}. Install CascadeGuard to ${BOLD}${CASCADEGUARD_HOME}${RESET}\n"
    STEP=$((STEP + 1))
    if [ -n "$LINK_DIR" ]; then
      printf "    ${STEP}. Symlink ${BOLD}cascadeguard${RESET} and ${BOLD}cg${RESET} into ${BOLD}${LINK_DIR}${RESET}\n"
      STEP=$((STEP + 1))
    fi
  fi

  if [ "$DO_SCAN" -eq 1 ]; then
    printf "    ${STEP}. Scan the current directory for container artifacts\n"
    STEP=$((STEP + 1))
  fi

  if [ "$DO_INSTALL" -eq 0 ] && [ "$DO_SCAN" -eq 1 ]; then
    printf "\n"
    printf "  ${DIM}Using a temporary environment (cleaned up after).${RESET}\n"
  fi

  if [ "$DO_INSTALL" -eq 0 ] && [ "$DO_SCAN" -eq 0 ]; then
    printf "    ${DIM}(nothing selected)${RESET}\n"
  fi

  printf "\n"
}

_configure_options() {
  printf "\n"
  printf "  ${BOLD}Configure${RESET}\n"
  printf "  ──────────────────────────────────────\n"

  # Toggle install
  if [ "$DO_INSTALL" -eq 1 ]; then
    printf "  1. [${GREEN}on${RESET}]  Install permanently\n"
  else
    printf "  1. [${DIM}off${RESET}] Install permanently\n"
  fi

  # Toggle scan
  if [ "$DO_SCAN" -eq 1 ]; then
    printf "  2. [${GREEN}on${RESET}]  Scan current directory\n"
  else
    printf "  2. [${DIM}off${RESET}] Scan current directory\n"
  fi

  printf "  ──────────────────────────────────────\n"
  printf "\n"
  printf "  ${BOLD}Toggle (1/2), or press Enter to continue:${RESET} "
  read -r toggle </dev/tty

  case "$toggle" in
    1)
      if [ "$DO_INSTALL" -eq 1 ]; then DO_INSTALL=0; else DO_INSTALL=1; fi
      _configure_options
      ;;
    2)
      if [ "$DO_SCAN" -eq 1 ]; then DO_SCAN=0; else DO_SCAN=1; fi
      _configure_options
      ;;
    *)
      printf "\n"
      # Re-show the plan and confirm
      _print_plan
      printf "  ${BOLD}Proceed? [Y/n/c]${RESET}  ${DIM}(c = configure)${RESET} "
      read -r answer </dev/tty
      case "$answer" in
        [nN]*) printf "\n"; info "Cancelled."; exit 0 ;;
        [cC]*) _configure_options ;;
        *)     printf "\n" ;;
      esac
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Symlink into the resolved LINK_DIR
# ---------------------------------------------------------------------------
link_to_path() {
  VENV_BIN="$1"
  TARGET="${VENV_BIN}/cascadeguard"
  CG_TARGET="${VENV_BIN}/cg"

  if command -v cascadeguard >/dev/null 2>&1; then
    EXISTING="$(command -v cascadeguard)"
    if [ -L "$EXISTING" ]; then
      ln -sf "$TARGET" "$EXISTING"
      ok "Updated symlink: ${EXISTING} → ${TARGET}"
    else
      ok "cascadeguard already on PATH at ${EXISTING}"
    fi
  else
    if [ -z "$LINK_DIR" ]; then
      warn "Could not find a writable directory on PATH to symlink into"
      warn "Run manually:  ln -s ${TARGET} /usr/local/bin/cascadeguard"
      warn "Run manually:  ln -s ${CG_TARGET} /usr/local/bin/cg"
      return 1
    fi
    ln -sf "$TARGET" "${LINK_DIR}/cascadeguard"
    ok "Linked: ${LINK_DIR}/cascadeguard → ${TARGET}"
  fi

  # Also create/update the cg shorthand symlink
  if command -v cg >/dev/null 2>&1; then
    EXISTING_CG="$(command -v cg)"
    if [ -L "$EXISTING_CG" ]; then
      ln -sf "$CG_TARGET" "$EXISTING_CG"
      ok "Updated symlink: ${EXISTING_CG} → ${CG_TARGET}"
    else
      ok "cg already on PATH at ${EXISTING_CG}"
    fi
  elif [ -n "$LINK_DIR" ]; then
    ln -sf "$CG_TARGET" "${LINK_DIR}/cg"
    ok "Linked: ${LINK_DIR}/cg → ${CG_TARGET}"
  fi
}

# ---------------------------------------------------------------------------
# Install CascadeGuard
# ---------------------------------------------------------------------------
do_install() {
  VENV_DIR="${CASCADEGUARD_HOME}/venv"
  VENV_BIN="${VENV_DIR}/bin"

  if [ -x "${VENV_BIN}/cascadeguard" ]; then
    info "Existing installation found, upgrading..."
    "$VENV_BIN/pip" install --quiet --disable-pip-version-check \
      --force-reinstall \
      "cascadeguard-tool @ git+${CASCADEGUARD_REPO}@${CASCADEGUARD_BRANCH}#subdirectory=app"
    ok "Upgraded cascadeguard-tool"
  else
    info "Installing to ${CASCADEGUARD_HOME}..."
    mkdir -p "${CASCADEGUARD_HOME}"
    "$PYTHON" -m venv "${VENV_DIR}"
    "$VENV_BIN/pip" install --quiet --disable-pip-version-check \
      "cascadeguard-tool @ git+${CASCADEGUARD_REPO}@${CASCADEGUARD_BRANCH}#subdirectory=app"
    ok "Installed cascadeguard-tool to ${CASCADEGUARD_HOME}"
  fi

  link_to_path "${VENV_BIN}"
}

# ---------------------------------------------------------------------------
# Scan using installed or temp venv
# ---------------------------------------------------------------------------
do_scan() {
  # Determine which cascadeguard binary to use
  if [ "$DO_INSTALL" -eq 1 ]; then
    CG_BIN="${CASCADEGUARD_HOME}/venv/bin/cascadeguard"
  else
    # Temp venv for scan-only mode
    TMPDIR_CG="$(mktemp -d 2>/dev/null || mktemp -d -t cascadeguard)"
    trap 'rm -rf "$TMPDIR_CG"' EXIT INT TERM

    info "Creating temporary environment..."
    "$PYTHON" -m venv "${TMPDIR_CG}/venv"

    VENV_BIN="${TMPDIR_CG}/venv/bin"
    info "Installing cascadeguard from GitHub (${CASCADEGUARD_BRANCH})..."
    "$VENV_BIN/pip" install --quiet --disable-pip-version-check \
      "cascadeguard-tool @ git+${CASCADEGUARD_REPO}@${CASCADEGUARD_BRANCH}#subdirectory=app"
    ok "Installed cascadeguard-tool (temporary)"

    CG_BIN="${VENV_BIN}/cascadeguard"
  fi

  info "Running: cascadeguard scan${SCAN_ARGS}"
  printf "\n"
  # shellcheck disable=SC2086
  "$CG_BIN" scan $SCAN_ARGS
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  printf "\n"
  printf "  ${BOLD}CascadeGuard${RESET} — Repository Scanner\n"
  printf "  https://cascadeguard.com\n"

  detect_platform
  check_python
  check_git
  check_docker
  print_environment

  if [ -z "$PYTHON" ]; then
    die "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ is required. Install from https://python.org"
  fi

  # Resolve symlink target before confirming
  find_link_dir || true

  confirm_proceed

  # Nothing to do?
  if [ "$DO_INSTALL" -eq 0 ] && [ "$DO_SCAN" -eq 0 ]; then
    info "Nothing to do."
    exit 0
  fi

  # Install first, then scan
  if [ "$DO_INSTALL" -eq 1 ]; then
    do_install
  fi

  if [ "$DO_SCAN" -eq 1 ]; then
    do_scan
  fi
}

main
