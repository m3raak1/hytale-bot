run-log:
	RUST_LOG=hytale_bot=debug,quinn=info,rustls=warn cargo run

run:
	cargo run

build:
	cargo build
