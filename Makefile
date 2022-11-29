install-dev:
	@cargo build
	@rm -f ~/.cargo/bin/cella && cp ./target/debug/cella ~/.cargo/bin/

cov:
	@cargo llvm-cov nextest --all-features --workspace --lcov --output-path coverage/lcov-$(shell date +%F).info

test:
	@CELLA_ENV=test cargo nextest run --all-features

release:
	@cargo release tag --execute
	@git cliff -o CHANGELOG.md
	@git commit -a -m "Update CHANGELOG.md" || true
	@git push origin master
	@cargo release push --execute

.PHONY: install-dev cov test release
