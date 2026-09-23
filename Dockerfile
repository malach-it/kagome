FROM rust:1-alpine3.24 AS builder

RUN apk add --no-cache cmake make perl

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && touch src/lib.rs
RUN cargo fetch --locked
RUN cargo build --release --locked
RUN cargo clean --release -p kagome
COPY src ./src
COPY templates/base.html templates/authorization_error.html templates/wallet_authorization.html ./templates/
RUN cargo build --release --locked

FROM alpine:3.24

RUN apk add --no-cache ca-certificates \
    && addgroup --system --gid 10001 kagome \
    && adduser --system --disabled-password --no-create-home --uid 10001 --ingroup kagome kagome \
    && mkdir /templates \
    && chown kagome:kagome /templates

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome

ENV KAGOME_CONFIG=/run/secrets/kagome.yaml
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT}

USER 10001:10001

CMD ["kagome"]
