PYTHON ?= python3

.PHONY: install-dev build-native test test-py test-rust lint typecheck info

install-dev:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

build-native:
	maturin develop

test: test-py test-rust

test-py:
	pytest

test-rust:
	cargo test -p ix_crypto

lint:
	ruff check src tests

typecheck:
	mypy src

info:
	ix-operator info
