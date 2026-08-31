FROM ghcr.io/malach-it/boruta-gateway:kubernetes-ingress-controller.alpha.16 AS gateway

FROM rust:1-alpine AS builder

RUN apk add --no-cache build-base

WORKDIR /app
COPY . .
RUN cargo build --release

FROM rust:1-alpine AS runtime

RUN apk add --no-cache liblksctp ncurses-libs openssl

COPY --from=gateway /app /gateway
COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome
COPY docker/boruta.yml /etc/boruta/gateway.yml
COPY docker/entrypoint.sh /usr/local/bin/kagome-gateway

RUN chmod +x /usr/local/bin/kagome-gateway

ENV KAGOME_SERVER_ADDRESS=127.0.0.1:4000
ENV KAGOME_WORKERS=4
ENV PORT=8044

EXPOSE $PORT

CMD ["kagome-gateway"]
