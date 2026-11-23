.PHONY: test unit integration verify pins clean

test: unit integration

unit:
	G02_REPO_ROOT=$$(cd ../.. && pwd) .venv/bin/python -m pytest tests -q -m "not integration"

integration:
	G02_REPO_ROOT=$$(cd ../.. && pwd) G02_PODMAN=1 .venv/bin/python -m pytest tests -q -m integration

verify:
	./scripts/verify.sh

pins:
	./scripts/pins.sh

clean:
	rm -rf .venv .pytest_cache __pycache__ */__pycache__
