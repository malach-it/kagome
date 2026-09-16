FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && touch src/lib.rs
RUN cargo fetch --locked
RUN cargo build --release --locked
RUN cargo clean --release -p kagome
COPY src ./src
COPY templates/base.html templates/authorization_error.html templates/wallet_authorization.html ./templates/
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 kagome \
    && useradd --system --uid 10001 --gid kagome --no-create-home --home-dir /nonexistent kagome \
    && mkdir /templates \
    && chown kagome:kagome /templates

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome

ENV KAGOME_CONFIG=/run/secrets/kagome.yaml
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT}

USER 10001:10001

CMD ["kagome"]
