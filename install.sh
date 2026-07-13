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
# `python3 -m venv` needs the venv module (a separate package on Debian/Ubuntu)
python3 -m venv --help >/dev/null 2>&1 || need="$need venv"

if [ -n "$need" ]; then
  say "installing prerequisites:$need"
  SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq && $SUDO apt-get install -y -qq git python3 python3-venv
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
if [ ! -d .venv ]; then
  say "creating virtualenv (.venv)"
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
