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

ARG KAGOME_UID=10001
ARG KAGOME_GID=10001

RUN apk add --no-cache ca-certificates dropbear \
    && addgroup --gid "$KAGOME_GID" kagome \
    && adduser --disabled-password --uid "$KAGOME_UID" --ingroup kagome --shell /bin/sh kagome \
    && mkdir -m 0700 /home/kagome/.ssh \
    && mkdir /templates \
    && mkdir -m 0700 /run/kagome-ssh \
    && chown kagome:kagome /home/kagome/.ssh /run/kagome-ssh /templates

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/kagome-entrypoint
COPY --chmod=755 docker-ssh-resource.sh /usr/local/bin/kagome-ssh-resource

ENV KAGOME_CONFIG=/run/secrets/kagome.yaml
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT} 2222

USER ${KAGOME_UID}:${KAGOME_GID}

ENTRYPOINT ["kagome-entrypoint"]
CMD ["kagome"]
