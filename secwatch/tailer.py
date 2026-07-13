"""Async tail -F for the Traefik access log, with rotation handling."""
import asyncio
import logging
import os
import subprocess

from . import config

log = logging.getLogger("secwatch.tailer")


async def follow(path, initial_state=None, start_at_end=False):
    """Yield (line, inode, offset). Yields ("", inode, offset) heartbeats when idle.

    initial_state: (inode, offset) persisted from a previous run; resumed only
    if the inode still matches (otherwise the file was rotated — start at 0).
    start_at_end: with no usable initial_state, skip existing content instead
    of replaying it (used for auth.log, which predates secwatch).
    """
    state = initial_state
    first_open = True
    while True:
        try:
            f = open(path, "r", errors="replace")
        except FileNotFoundError:
            await asyncio.sleep(2)
            continue
        with f:
            ino = os.fstat(f.fileno()).st_ino
            if state and state[0] == ino and state[1] <= os.fstat(f.fileno()).st_size:
                f.seek(state[1])
            elif start_at_end and first_open:
                f.seek(0, os.SEEK_END)
            state = None
            first_open = False
            log.info("tailing %s (inode %d, offset %d)", path, ino, f.tell())
            while True:
                line = f.readline()
                if line:
                    if line.endswith("\n"):
                        yield line, ino, f.tell()
                    else:
                        # partial write — rewind and retry next tick
                        f.seek(f.tell() - len(line))
                        await asyncio.sleep(0.5)
                    continue
                yield "", ino, f.tell()
                try:
                    cur = os.stat(path)
                except FileNotFoundError:
                    cur = None
                if cur is None or cur.st_ino != ino or cur.st_size < f.tell():
                    log.info("log rotated/truncated, reopening")
                    break
                await asyncio.sleep(1.0)


async def rotate_if_needed():
    """Size-based rotation: rename, then signal Traefik to reopen its log fd."""
    path = config.ACCESS_LOG
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    if size < config.LOG_ROTATE_BYTES:
        return
    rotated = path.with_suffix(path.suffix + ".1")
    log.info("rotating %s (%d bytes)", path, size)
    try:
        os.replace(path, rotated)
    except OSError as exc:
        log.error("rotate rename failed: %s", exc)
        return
    proc = await asyncio.create_subprocess_exec(
        "docker", "kill", "-s", "USR1", config.TRAEFIK_CONTAINER,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        log.error("USR1 to traefik failed: %s", err.decode().strip())
