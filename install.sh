#!/bin/sh
# secwatch installer — one command to set up everything: OS prerequisites
# (git, python3, venv), a virtualenv, and the Python dependencies. Then it runs
# the first-run wizard (unless you pass --no-wizard).
#
#   git clone https://github.com/Paco5687/secwatch && cd secwatch
#   ./install.sh
#
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
say() { printf '[secwatch] %s\n' "$1"; }

# ---- 1. prerequisites ----------------------------------------------------
need=""
command -v git >/dev/null 2>&1 || need="$need git"
command -v python3 >/dev/null 2>&1 || need="$need python3"
# `venv --help` passes even without ensurepip — test ensurepip itself (the bit
# Debian/Ubuntu split into a separate python3-venv package).
python3 -c "import ensurepip" >/dev/null 2>&1 || need="$need venv"

if [ -n "$need" ]; then
  say "installing prerequisites:$need"
  SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
  if command -v apt-get >/dev/null 2>&1; then
    # newer distros need the version-specific venv package (e.g. python3.14-venv)
    PYVER=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true)
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq git python3 python3-venv python3-pip
    [ -n "$PYVER" ] && $SUDO apt-get install -y -qq "python${PYVER}-venv" 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y -q git python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -Sy --noconfirm git python
  else
    say "couldn't find apt/dnf/pacman — please install git + python3 + python3-venv, then re-run"
    exit 1
  fi
fi

# ---- 2. virtualenv + dependencies ---------------------------------------
# (re)create the venv if it's missing OR broken (a half-made .venv has no pip)
if [ ! -x .venv/bin/pip ]; then
  say "creating virtualenv (.venv)"
  rm -rf .venv
  python3 -m venv .venv
fi
say "installing Python dependencies"
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

say "setup complete."

# ---- 3. first-run wizard (interactive only) -----------------------------
if [ "$1" = "--no-wizard" ]; then
  echo
  say "next: configure + run it with"
  say "   .venv/bin/python -m secwatch.install    # first-run wizard (port, login, auto-detect)"
  exit 0
fi
if [ -t 0 ]; then
  echo
  say "starting the first-run wizard..."
  exec .venv/bin/python -m secwatch.install
else
  echo
  say "next (from this directory):  .venv/bin/python -m secwatch.install"
fi
