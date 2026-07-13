# secwatch — portable security monitor.
# Runs the "core" (detection/dashboard/CVE/LLM/alerting) cleanly in a container.
# Host-level collectors (auth/persistence/process/docker) need host visibility —
# either run this one container with host access (see docker-compose.yml) or run
# `python -m secwatch.agent` on the host and this as MODE=core. See README.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY secwatch/ ./secwatch/
COPY secwatch.example.yaml ./

# non-root; data dir for the sqlite db + caches
RUN useradd -u 10001 -r -m -s /usr/sbin/nologin secwatch \
    && mkdir -p /app/data && chown -R secwatch:secwatch /app
USER secwatch

EXPOSE 8931
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8931/healthz',timeout=3).status==200 else 1)"

# NOTE: the CVE scanner + docker watch shell out to `docker`; mount the socket and
# add a docker CLI (or run those via the host agent) to enable them. They degrade
# gracefully (log + skip) if docker is unavailable.
CMD ["python", "-m", "secwatch.main"]
