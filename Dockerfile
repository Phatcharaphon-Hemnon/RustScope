FROM rust:1.99.1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY templates/ templates/
COPY migrations/ migrations/
COPY fixtures/ fixtures/
COPY examples/reports/fixed.pdf examples/reports/fixed.pdf
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/rustscope
COPY --from=builder /build/target/release/rustscope /usr/local/bin/rustscope
ENV RUSTSCOPE_BIND=0.0.0.0 \
    RUSTSCOPE_PORT=3100 \
    RUSTSCOPE_STATE=/var/lib/rustscope
USER 10001:10001
EXPOSE 3100
ENTRYPOINT ["/usr/local/bin/rustscope"]
