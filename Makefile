.PHONY: test test-unit test-integration install uninstall demo clean

test:              ## full suite (run with sudo for eBPF/root tests)
	./run_tests.sh all

test-unit:
	./run_tests.sh unit

test-integration:
	./run_tests.sh integration

install:           ## install + start the systemd service (needs root)
	./install.sh

uninstall:
	./install.sh --uninstall

demo:              ## run the simulated attack sequence against the installed agent
	./demo/attack_simulation.sh

clean:
	find . -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache *.egg-info build dist
