FROM rust:1-bookworm AS builder

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release
RUN scripts/generate-crypto-config.sh /app/kagome.crypto.yaml

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome
COPY --from=builder /app/kagome.example.yaml /etc/kagome/kagome.yaml
COPY --from=builder /app/kagome.crypto.yaml /etc/kagome/kagome.crypto.yaml
COPY --from=builder /app/kagome.htpasswd.example /etc/kagome/kagome.htpasswd.example
COPY --from=builder /app/templates/*.html /templates/

ENV KAGOME_CONFIG=/etc/kagome/kagome.yaml
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT}

CMD ["kagome"]
