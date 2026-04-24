FROM python:3.12-slim

# uv handles the Python deps via the PEP-723 header in declaw.py
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        default-jre-headless \
        adb \
        usbutils \
        xz-utils \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY declaw.py /app/

# utils/ is declared as a volume so the cached apktool, signer, gadget, and
# bypass bundle survive across runs.
RUN mkdir -p /app/utils /app/packages /app/patched
VOLUME ["/app/utils"]

ENV UV_SYSTEM_PYTHON=1 \
    UV_NO_CACHE_DIR=1

EXPOSE 5037

ENTRYPOINT ["uv", "run", "--no-project", "declaw.py"]
