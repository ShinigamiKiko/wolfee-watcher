
FROM python:3.11-slim AS builder

ARG HONEYPOTS_VERSION=

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc python3-dev libffi-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "honeypots${HONEYPOTS_VERSION:+==$HONEYPOTS_VERSION}"

FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libffi8 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN mkdir -p /var/log/honeypots /etc/honeypot && chmod 0777 /var/log/honeypots /tmp

ENTRYPOINT ["python3", "-m", "honeypots"]
