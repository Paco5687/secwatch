#!/bin/sh
# secwatch installer — ONE command: installs everything and auto-starts secwatch
# as a background service, then prints the URL. No prompts, no follow-up steps.
#
#   curl -fsSL https://raw.githubusercontent.com/Paco5687/secwatch/main/install.sh | sudo sh
#
# or from a checkout:   git clone https://github.com/Paco5687/secwatch && cd secwatch && ./install.sh
#
# By default it uses uv (Astral) to fetch a pinned, self-contained Python — so the
# host's Python version/packaging is irrelevant. Falls back to the system python3
# if uv can't be used (offline, or SECWATCH_NO_UV=1).
#
# Env: SECWATCH_PORT, SECWATCH_ADMIN_PASSWORD, SECWATCH_NO_AUTH=1,
#      SECWATCH_NO_START=1, SECWATCH_DIR, SECWATCH_NO_UV=1
set -e
REPO="${SECWATCH_REPO:-https://github.com/Paco5687/secwatch.git}"
PYPIN="3.12"
say() { printf '[secwatch] %s\n' "$1"; }

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
SUDO=""; [ "$IS_ROOT" -eq 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
IN_CHECKOUT=0
{ [ -f ./secwatch/__init__.py ] && [ -f ./requirements.txt ]; } && IN_CHECKOUT=1

# ---- 1. git (needed to fetch the code) ----------------------------------
if ! command -v git >/dev/null 2>&1; then
  say "installing git"
  if command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update -qq && $SUDO apt-get install -y -qq git
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y -q git
  elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm git
  else say "please install git, then re-run"; exit 1; fi
fi

# ---- 2. locate or fetch the code ----------------------------------------
if [ "$IN_CHECKOUT" -eq 1 ]; then
  DIR="$(pwd)"; RUN=""
else
  if [ "$IS_ROOT" -eq 0 ] && [ -z "$SUDO" ]; then
    say "run this as root:  curl -fsSL <url>/install.sh | sudo sh"; exit 1
  fi
  DIR="${SECWATCH_DIR:-/opt/secwatch}"; RUN="$SUDO"
  if [ -d "$DIR/.git" ]; then say "updating $DIR"; $SUDO git -C "$DIR" pull -q
  else say "cloning secwatch to $DIR"; $SUDO git clone -q "$REPO" "$DIR"; fi
fi
cd "$DIR"

# ---- 3. Python env: prefer uv (portable Python), else system python3 ----
UV=""
if [ "${SECWATCH_NO_UV:-0}" != "1" ] && [ ! -x .venv/bin/python ]; then
  UV="$(command -v uv 2>/dev/null || true)"
  if [ -z "$UV" ]; then
    say "installing uv (portable Python toolchain)"
    $RUN sh -c "export UV_INSTALL_DIR='$DIR/.uv'; curl -LsSf https://astral.sh/uv/install.sh | sh" >/dev/null 2>&1 || true
    [ -x "$DIR/.uv/uv" ] && UV="$DIR/.uv/uv"
  fi
  if [ -n "$UV" ]; then
    say "creating an isolated Python $PYPIN environment via uv"
    $RUN "$UV" venv --python "$PYPIN" .venv >/dev/null 2>&1 \
      || $RUN "$UV" venv .venv >/dev/null 2>&1 || UV=""
  fi
fi

if [ -z "$UV" ] && [ ! -x .venv/bin/pip ]; then
  # fallback: system python3 + venv
  need=""
  command -v python3 >/dev/null 2>&1 || need="$need python3"
  python3 -c "import ensurepip" >/dev/null 2>&1 || need="$need venv"
  if [ -n "$need" ]; then
    say "installing python3 + venv"
    if command -v apt-get >/dev/null 2>&1; then
      PYVER=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true)
      $SUDO apt-get update -qq
      $SUDO apt-get install -y -qq python3 python3-venv python3-pip
      [ -n "$PYVER" ] && $SUDO apt-get install -y -qq "python${PYVER}-venv" 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y -q python3 python3-pip
    elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm python
    else say "please install python3 + python3-venv, then re-run"; exit 1; fi
  fi
  $RUN rm -rf .venv 2>/dev/null || true
  $RUN python3 -m venv .venv
fi

# ---- 4. dependencies ----------------------------------------------------
say "installing dependencies (this can take a minute)"
if [ -n "$UV" ]; then
  $RUN "$UV" pip install -q --python .venv/bin/python -r requirements.txt
else
  $RUN .venv/bin/pip install -q --upgrade pip
  $RUN .venv/bin/pip install -q -r requirements.txt
fi

# ---- 5. configure + auto-start the service ------------------------------
set -- --non-interactive --force --port "${SECWATCH_PORT:-8931}"
[ "${SECWATCH_NO_START:-0}" = "1" ] && set -- "$@" --no-start || set -- "$@" --start
if [ -n "${SECWATCH_JOIN_URL:-}" ]; then
  set -- "$@" --no-auth --cluster-role "${SECWATCH_CLUSTER_ROLE:-peer}" \
             --join-url "$SECWATCH_JOIN_URL" --join-secret "${SECWATCH_JOIN_SECRET:-}"
else
  [ "${SECWATCH_NO_AUTH:-0}" = "1" ] && set -- "$@" --no-auth
  [ -n "${SECWATCH_ADMIN_PASSWORD:-}" ] && set -- "$@" --admin-password "${SECWATCH_ADMIN_PASSWORD}"
fi
$RUN .venv/bin/python -m secwatch.install "$@"
