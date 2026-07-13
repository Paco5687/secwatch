import logging

import uvicorn

from . import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

if __name__ == "__main__":
    uvicorn.run(
        "secwatch.web:app",
        host=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        log_level="warning",
    )
