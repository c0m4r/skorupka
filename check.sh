#!/bin/bash

set -euo pipefail

cargo install cargo-audit --locked
cargo clippy --release --all-targets
cargo audit
cargo test --release
cargo build --release
./target/release/skorupka check
./target/release/skorupka selftest
