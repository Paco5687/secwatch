import logging

import uvicorn

from . import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

if __name__ == "__main__":
    # Fail closed: never serve an unauthenticated dashboard to the network by accident.
    _reason = config.insecure_exposure_reason()
    if _reason:
        logging.getLogger("secwatch").error(_reason)
        raise SystemExit(1)
    uvicorn.run(
        "secwatch.web:app",
        host=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        log_level="warning",
    )
