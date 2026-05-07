FROM rust:1-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome

ENV KAGOME_SERVER_ADDRESS=0.0.0.0:4000
ENV KAGOME_WORKERS=4
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT}

CMD ["kagome"]
