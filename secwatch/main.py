import logging

import uvicorn

from . import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

if __name__ == "__main__":
    # Don't expose an unauthenticated dashboard to a PUBLIC network by accident — but
    # never crash-loop a monitor over it. On a public interface we fall back to
    # loopback (stays up, not exposed); on a private LAN we only warn (the operator's
    # call). Setting a password or SECWATCH_NO_AUTH=1 silences both.
    _log = logging.getLogger("secwatch")
    _reason = config.insecure_exposure_reason()
    if _reason and config.bind_is_public():
        _log.error("%s\n→ This looks like a PUBLIC interface — binding 127.0.0.1 only "
                   "so nothing is exposed. Set a password (or the opt-out above) to "
                   "serve it on the network.", _reason)
        config.LISTEN_HOST = "127.0.0.1"
    elif _reason:
        _log.warning("%s\n→ Serving on your local network without a login. This is "
                     "fine on a trusted LAN; set SECWATCH_NO_AUTH=1 to silence this "
                     "warning, or a password to lock it down.", _reason)
    uvicorn.run(
        "secwatch.web:app",
        host=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        log_level="warning",
    )
