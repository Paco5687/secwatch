"""Standalone dashboard auth — password hashing + signed session cookies, using
only the stdlib (no bcrypt/passlib dependency). Used when secwatch is exposed
directly on IP:port with no authenticating reverse proxy in front.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

from . import config

log = logging.getLogger("secwatch.auth")

PBKDF2_ITER = 200_000
COOKIE_NAME = "secwatch_session"


# ---- password hashing ---------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        assert algo == "pbkdf2_sha256"
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AssertionError):
        return False


# ---- session secret (persisted so sessions survive restarts) ------------

def _session_secret() -> bytes:
    path = config.BASE_DIR / "data" / "session_secret"
    try:
        if path.exists():
            return bytes.fromhex(path.read_text().strip())
    except (OSError, ValueError):
        pass
    secret = secrets.token_bytes(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secret.hex())
        os.chmod(path, 0o600)
    except OSError:
        log.warning("could not persist session secret; sessions won't survive restart")
    return secret


_SECRET = _session_secret()


# ---- signed session tokens ----------------------------------------------

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user: str, ttl: int = None) -> str:
    ttl = ttl if ttl is not None else config.AUTH_SESSION_TTL
    payload = _b64(json.dumps({"u": user, "exp": int(time.time()) + ttl}).encode())
    sig = _b64(hmac.new(_SECRET, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify_token(token: str):
    try:
        payload, sig = token.split(".", 1)
        expected = _b64(hmac.new(_SECRET, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_unb64(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("u")
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>secwatch — sign in</title>
<style>
:root{color-scheme:light dark}
body{font:15px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#0d0d0d;color:#eee}
@media (prefers-color-scheme:light){body{background:#f5f5f4;color:#111}}
form{background:#1a1a19;padding:28px 26px;border-radius:14px;width:300px;box-shadow:0 8px 30px rgba(0,0,0,.35)}
@media (prefers-color-scheme:light){form{background:#fff}}
h1{font-size:18px;margin:0 0 4px}p.sub{margin:0 0 18px;color:#8a8a86;font-size:13px}
label{display:block;font-size:12px;color:#8a8a86;margin:10px 0 4px}
input{width:100%;box-sizing:border-box;padding:9px 10px;border-radius:8px;border:1px solid #3336;background:#0d0d0d;color:inherit;font:inherit}
@media (prefers-color-scheme:light){input{background:#faf9f7}}
button{width:100%;margin-top:18px;padding:10px;border:0;border-radius:8px;background:#2a78d6;color:#fff;font:inherit;font-weight:600;cursor:pointer}
.err{color:#e66767;font-size:13px;margin-top:12px;min-height:1em}
</style></head><body>
<form method="post" action="AUTH_ACTION">
<h1>secwatch</h1><p class="sub">Sign in to the security dashboard</p>
<label>Username</label><input name="username" autofocus autocomplete="username">
<label>Password</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
<div class="err">ERR</div>
</form></body></html>"""


def login_page(error: str = "", action: str = "/auth/login") -> str:
    return LOGIN_HTML.replace("ERR", error).replace("AUTH_ACTION", action)
