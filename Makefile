BENCH_10=bench_cellar
GIT_BRANCH=$(strip $(shell git symbolic-ref --short HEAD))

$(BENCH_10):
	cargo bench --bench $@ --  --sample-size 10

pr:
	@git push origin $(GIT_BRANCH)
	@hub pull-request

link:
	@rm -f $(HOME)/.cargo/bin/cellar
	@ln -s $(HOME)/.target/debug/cellar $(HOME)/.cargo/bin/cellar

link-release:
	@rm -f $(HOME)/.cargo/bin/cellar
	@ln -s $(HOME)/.target/release/cellar $(HOME)/.cargo/bin/cellar
