# Development guide

## Run locally

Use Linux or WSL, stable Rust with Cargo, and a C toolchain. The Docker build pins its Rust version in [Dockerfile](../Dockerfile). The first native build fetches dependencies. Add `--offline` to Cargo commands once the locked dependencies are cached.

```sh
cargo run --locked
```

The native server defaults to `127.0.0.1:3100` and `./state`. Set `RUSTSCOPE_BIND`, `RUSTSCOPE_PORT`, and `RUSTSCOPE_STATE` to override those defaults. To provision a local account from the terminal, use `cargo run --locked -- account USER`. It prints the generated password once.

Run one instance per state directory or Compose volume. Back up the database, account files, and encryption key together in protected storage. Operational URLs depend on the key for recovery.

## Update interface styles

Edit the Askama templates in `templates/` and shared styles in `styles/tailwind.css`. Use the [Tailwind CSS v4.1.18 standalone CLI](https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.1.18) to regenerate the checked-in stylesheet when styles or utility classes change. Askama embeds the compiled CSS.

```sh
tailwindcss -i styles/tailwind.css -o templates/style.css --minify
cargo build --locked
```

For report changes, verify keyboard navigation, narrow screens, and A4 print with long identifiers and older stored evidence.

## Verify changes

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

For changes to scan submission, reports, permissions, or review, run the offline HTTP demo with Python 3 from the repository root. The script uses the default debug binary at `target/debug/rustscope` and starts a temporary loopback server.

```sh
cargo build --locked
python3 tests/demo.py --rounds-dir /tmp/rustscope-rounds
```

The same finding should progress through **New**, **Not comparable** after a 403, **Persistent**, and **Verified fixed**. Use `cargo test --locked evaluation:: -- --nocapture` to inspect the scores for the [labelled rule fixtures](../fixtures/evaluation). Follow the [advisory snapshot instructions](../fixtures/advisories/README.md) when updating bundled data.

## Publish the Docker image

The [Docker Hub workflow](../.github/workflows/docker-hub.yml) runs on pushes to `main` and can be dispatched manually for `main`. To enable publishing, create a Docker Hub repository named `rustscope`. Set the GitHub Actions variable `DOCKERHUB_USERNAME` and the secret `DOCKERHUB_TOKEN` to a token with write access. With the username unset, the workflow only builds. Published Linux x86-64 images get the `latest` and `sha-<full-commit>` tags.
