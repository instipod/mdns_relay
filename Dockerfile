# Test image. Integration tests need --privileged to create network namespaces.
# For deployment, run with --network host so the relay can see the real interfaces.
FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 procps avahi-daemon avahi-utils dbus curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY mdns_relay ./mdns_relay
COPY tests ./tests
RUN pip install --no-cache-dir ".[dev]"

CMD ["mdns-relay", "--help"]
