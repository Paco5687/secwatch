#!/bin/sh
# secwatch installer — ONE command: installs everything and auto-starts secwatch
# as a background service, then prints the URL. No prompts, no follow-up steps.
#
#   curl -fsSL https://raw.githubusercontent.com/Paco5687/secwatch/main/install.sh | sudo sh
#
# or from a checkout:   git clone https://github.com/Paco5687/secwatch && cd secwatch && ./install.sh
#
# Non-interactive defaults: port 8931, an auto-generated admin password (printed
# at the end). Override with env:
#   SECWATCH_PORT=9000   SECWATCH_ADMIN_PASSWORD=hunter2   SECWATCH_NO_AUTH=1
#   SECWATCH_DIR=/opt/secwatch   SECWATCH_NO_START=1 (set up but don't start)
set -e
REPO="${SECWATCH_REPO:-https://github.com/Paco5687/secwatch.git}"
say() { printf '[secwatch] %s\n' "$1"; }

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
SUDO=""; [ "$IS_ROOT" -eq 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
IN_CHECKOUT=0
{ [ -f ./secwatch/__init__.py ] && [ -f ./requirements.txt ]; } && IN_CHECKOUT=1

# ---- 1. prerequisites ----------------------------------------------------
need=""
command -v git >/dev/null 2>&1 || need="$need git"
command -v python3 >/dev/null 2>&1 || need="$need python3"
python3 -c "import ensurepip" >/dev/null 2>&1 || need="$need venv"
if [ -n "$need" ]; then
  say "installing prerequisites:$need"
  if command -v apt-get >/dev/null 2>&1; then
    PYVER=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true)
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq git python3 python3-venv python3-pip
    [ -n "$PYVER" ] && $SUDO apt-get install -y -qq "python${PYVER}-venv" 2>/dev/null || true
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y -q git python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm git python
  else say "please install git + python3 + python3-venv, then re-run"; exit 1; fi
fi

# ---- 2. locate or fetch the code ----------------------------------------
if [ "$IN_CHECKOUT" -eq 1 ]; then
  DIR="$(pwd)"; RUN=""                    # use this checkout, as the current user
else
  # piped install (curl|sh) — clone to a system dir, which needs root
  if [ "$IS_ROOT" -eq 0 ] && [ -z "$SUDO" ]; then
    say "run this as root:  curl -fsSL <url>/install.sh | sudo sh"; exit 1
  fi
  DIR="${SECWATCH_DIR:-/opt/secwatch}"; RUN="$SUDO"
  if [ -d "$DIR/.git" ]; then say "updating $DIR"; $SUDO git -C "$DIR" pull -q
  else say "cloning secwatch to $DIR"; $SUDO git clone -q "$REPO" "$DIR"; fi
fi
cd "$DIR"

# ---- 3. virtualenv + dependencies ---------------------------------------
if [ ! -x .venv/bin/pip ]; then
  say "creating virtualenv"; $RUN rm -rf .venv; $RUN python3 -m venv .venv
fi
say "installing dependencies (this can take a minute)"
$RUN .venv/bin/pip install -q --upgrade pip
$RUN .venv/bin/pip install -q -r requirements.txt

# ---- 4. configure + auto-start the service ------------------------------
set -- --non-interactive --force --port "${SECWATCH_PORT:-8931}"
[ "${SECWATCH_NO_START:-0}" = "1" ] && set -- "$@" --no-start || set -- "$@" --start
if [ -n "${SECWATCH_JOIN_URL:-}" ]; then
  # cluster enrollment: no dashboard login by default, join after config
  set -- "$@" --no-auth --cluster-role "${SECWATCH_CLUSTER_ROLE:-peer}" \
             --join-url "$SECWATCH_JOIN_URL" --join-secret "${SECWATCH_JOIN_SECRET:-}"
else
  [ "${SECWATCH_NO_AUTH:-0}" = "1" ] && set -- "$@" --no-auth
  [ -n "${SECWATCH_ADMIN_PASSWORD:-}" ] && set -- "$@" --admin-password "${SECWATCH_ADMIN_PASSWORD}"
fi
$RUN .venv/bin/python -m secwatch.install "$@"
