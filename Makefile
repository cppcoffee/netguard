PHONY := all

all: debug

check:
	cargo check

debug:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

test:
	cargo test

rsync:
	rsync -av --exclude='target' ../netguard vm:/home/vagrant/

