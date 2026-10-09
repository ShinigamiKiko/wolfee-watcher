
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

COPY honeypot/docker-entrypoint.sh honeypot/docker-healthcheck /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-healthcheck  && mkdir -p /var/log/honeypots /etc/honeypot  && for d in postgres mysql redis elastic dns ssh http ftp smtp; do mkdir -p /var/log/$d; done  && chmod 0777 /var/log/honeypots /var/log/postgres /var/log/mysql /var/log/redis /var/log/elastic /var/log/dns /var/log/ssh /var/log/http /var/log/ftp /var/log/smtp /tmp

USER 65534:65534
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
