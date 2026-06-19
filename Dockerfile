FROM rust:1-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome
COPY --from=builder /app/target/release/kagome-login /usr/local/bin/kagome-login

ENV KAGOME_SERVER_ADDRESS=0.0.0.0:4000
ENV KAGOME_LOGIN_SERVER_ADDRESS=127.0.0.1:4000
ENV KAGOME_LOOPBACK_SERVER_ADDRESS=127.0.0.1:4001
ENV KAGOME_WORKERS=4
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT}

CMD ["kagome"]
