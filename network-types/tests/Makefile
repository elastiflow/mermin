build:
	sudo --preserve-env=PATH env CARGO_HOME="$$HOME/.cargo" RUSTUP_HOME="$$HOME/.rustup" $$(which cargo) -Z build-std=core build -p integration-ebpf --release --target bpfel-unknown-none

clean:
	sudo --preserve-env=PATH env CARGO_HOME="$$HOME/.cargo" RUSTUP_HOME="$$HOME/.rustup" $$(which cargo) clean

test:
	sudo --preserve-env=PATH env CARGO_HOME="$$HOME/.cargo" RUSTUP_HOME="$$HOME/.rustup" RUST_LOG=info,integration=debug $$(which cargo) test -p integration -- --test-threads=1 --nocapture

test-ci: build test
