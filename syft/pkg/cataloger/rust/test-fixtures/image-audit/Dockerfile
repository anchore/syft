FROM rust:1.82.0 AS builder

WORKDIR /app

RUN cargo install cargo-auditable --version 0.6.4 --locked
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release

FROM scratch

COPY --from=builder /app/target/release/hello_world /usr/local/bin/hello_world

