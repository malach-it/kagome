FROM rust:1-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kagome /usr/local/bin/kagome
COPY --from=builder /app/kagome.example.yaml /etc/kagome/kagome.yaml

ENV KAGOME_CONFIG=/etc/kagome/kagome.yaml
ENV KAGOME_PORT=4000

EXPOSE ${KAGOME_PORT}

CMD ["kagome"]
