"""In-app editable settings — an overrides layer above secwatch.yaml.

Two stores under the data dir:
  settings.json  — non-secret overrides, dotted-key -> JSON value (plaintext).
  secrets.enc    — secret overrides, Fernet-encrypted with settings.key.
  settings.key   — the Fernet key, chmod 600, generated on first secret write.

Config precedence (see config.py): env var > THESE overrides > secwatch.yaml > default.
The UI edits this layer; your hand-written secwatch.yaml stays the declarative base.

Honest crypto note: the decrypt key lives next to the ciphertext (a 600 keyfile)
so the service can start unattended. This keeps secrets out of plaintext files
and backups — it is NOT protection against an attacker who already has host
access (they can read the key too). Treat it as at-rest hygiene, not a vault.

This module imports NOTHING from secwatch (no import cycle with config).
"""
import json
import logging
import os
from pathlib import Path

log = logging.getLogger("secwatch.settings")

_BASE = Path(os.environ.get("SECWATCH_DB", "")).parent if os.environ.get("SECWATCH_DB") \
    else Path(__file__).resolve().parents[1] / "data"
SETTINGS_FILE = _BASE / "settings.json"
SECRETS_FILE = _BASE / "secrets.enc"
KEY_FILE = _BASE / "settings.key"

# Which dotted keys are secrets (stored encrypted, never returned in the clear).
SECRET_KEYS = {"alerting.discord_webhook_url", "llm.api_key"}


# --------------------------------------------------------------------------
# non-secret overrides
# --------------------------------------------------------------------------

def _load_json():
    try:
        with open(SETTINGS_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_json(d):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2, sort_keys=True)
    os.replace(tmp, SETTINGS_FILE)


# --------------------------------------------------------------------------
# encrypted secrets
# --------------------------------------------------------------------------

def crypto_available():
    try:
        import cryptography.fernet  # noqa: F401
        return True
    except ImportError:
        return False


def _fernet():
    """Return a Fernet using the on-disk key, creating the key on first use."""
    from cryptography.fernet import Fernet
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        # write 600 BEFORE data lands in it
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    return Fernet(key)


def _load_secrets():
    """Decrypt and return the secrets dict, or {} if unavailable/empty."""
    if not SECRETS_FILE.exists() or not crypto_available():
        return {}
    try:
        from cryptography.fernet import InvalidToken
        raw = SECRETS_FILE.read_bytes()
        if not raw:
            return {}
        try:
            data = _fernet().decrypt(raw)
        except InvalidToken:
            log.error("secrets.enc could not be decrypted with settings.key "
                      "(key rotated or file corrupt) — ignoring stored secrets")
            return {}
        d = json.loads(data)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError) as exc:
        log.error("failed reading secrets.enc: %s", exc)
        return {}


def _save_secrets(d):
    f = _fernet()
    tmp = SECRETS_FILE.with_suffix(".enc.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(f.encrypt(json.dumps(d).encode()))
    os.replace(tmp, SECRETS_FILE)


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def load_overrides():
    """Merged dotted-key -> value dict (non-secret + decrypted secret) for config."""
    out = dict(_load_json())
    out.update(_load_secrets())
    return out


def is_secret(key):
    return key in SECRET_KEYS


def secret_status():
    """{secret_key: bool_is_set} — never returns the values themselves."""
    have = _load_secrets()
    return {k: bool(str(have.get(k, "")).strip()) for k in SECRET_KEYS}


def set_value(key, value):
    """Persist one override. Secrets go to the encrypted store, else JSON."""
    if key in SECRET_KEYS:
        if not crypto_available():
            raise RuntimeError("cryptography is not installed — cannot store "
                               "secrets encrypted (pip install cryptography)")
        d = _load_secrets()
        if value is None or value == "":
            d.pop(key, None)
        else:
            d[key] = value
        _save_secrets(d)
    else:
        d = _load_json()
        if value is None:
            d.pop(key, None)
        else:
            d[key] = value
        _save_json(d)


def clear(key):
    set_value(key, None if key in SECRET_KEYS else None)
