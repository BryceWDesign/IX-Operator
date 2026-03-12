# IX-Operator

IX-Operator is a secure operator platform for autonomous agents.

This repository is being rebuilt from square one as a clean monorepo with four
core layers:

- `ix_crypto` — Rust cryptographic core
- `ix_session` — Python session and handshake layer
- `ix_transport` — Python transport and message framing layer
- `ix_runtime` — Python IX runtime, orchestration, and CLI layer

## Status

Pre-alpha rebuild.

The goal of v1 is not to look flashy. The goal is to be small, testable,
honest, and secure by construction.

## v1 design rules

- One real cryptographic core
- One real handshake and session state machine
- One real message framing format
- One real IX runtime
- No placeholder security claims
- No raw `eval`
- No nonce reuse
- No direct use of shared secrets without a KDF
- No hidden destructive behavior

## Explicit non-goals for v1

IX-Operator v1 does **not** include:

- covert channels
- anti-analysis behavior
- trap payloads
- destructive “kill-switch” behavior
- self-rewriting agents
- mock post-quantum claims
- custom production cipher implementations for CBC/CTR/GCM

If those topics ever appear in old notes or prototype repos, they are not part
of the clean rebuild.

## Repository layout

```text
IX-Operator/
├── .github/
│   └── workflows/
│       └── ci.yml
├── crates/
│   └── ix_crypto/
│       ├── Cargo.toml
│       └── src/
│           ├── bindings.rs
│           └── lib.rs
├── examples/
│   └── genesis.ix
├── src/
│   └── ix_operator/
│       ├── __init__.py
│       ├── __main__.py
│       ├── app.py
│       ├── bus.py
│       ├── crypto/
│       ├── agents/
│       ├── ix/
│       ├── session/
│       └── transport/
├── tests/
├── .editorconfig
├── .gitignore
├── Cargo.toml
├── LICENSE
├── Makefile
├── pyproject.toml
└── README.md

Build and development

IX-Operator now uses maturin so the Rust extension and Python package are
built together correctly.

Create a development environment and install dependencies:
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

Build and install the native extension for development:
maturin develop

Run the Python test suite:
pytest

Run the Rust test suite:
cargo test -p ix_crypto

cargo test -p ix_crypto
ix-operator info

Initialize a node identity:
ix-operator identity init --peer-id node-alpha

Run the example script:
ix-operator run-script examples/genesis.ix

Continuous integration

GitHub Actions now runs:

Ruff linting

MyPy typechecking

Python tests

Rust tests

release wheel builds through maturin

The CI workflow lives at .github/workflows/ci.yml.

Current CLI surface

The current CLI provides:

ix-operator info

ix-operator identity init

ix-operator identity show

ix-operator run-script <path>

Long-term result

When complete, IX-Operator should be a serious, self-hosted operator platform
for autonomous agents that can:

launch agents under one runtime

establish authenticated sessions correctly

move messages through a clear transport layer

keep cryptographic responsibilities contained and auditable

remain understandable to other engineers reading the code

That is the bar.
