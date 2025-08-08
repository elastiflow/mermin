build:
	cargo -Z build-std=core build -p integration-ebpf --release --target bpfel-unknown-none

test:
	sudo --preserve-env=PATH env CARGO_HOME="$HOME/.cargo" RUSTUP_HOME="$HOME/.rustup" RUST_LOG=info,integration=debug $(which cargo) test -p integration -- --test-threads=1 --nocapture
