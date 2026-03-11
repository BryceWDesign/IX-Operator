# IX-Operator

IX-Operator is a secure operator platform for autonomous agents.

This repository is being rebuilt from square one as a clean monorepo with four
core layers:

- `ix_crypto` — Rust cryptographic core
- `ix_session` — Python session and handshake layer
- `ix_transport` — Python transport and message framing layer
- `ix_runtime` — Python IX runtime, orchestration, and CLI layer

## Status

Bootstrap stage.

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
├── crates/
│   └── ix_crypto/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs
├── src/
│   └── ix_operator/
│       ├── __init__.py
│       └── __main__.py
├── .editorconfig
├── .gitignore
├── Cargo.toml
├── LICENSE
├── pyproject.toml
└── README.md

Initial commands

Run the Python bootstrap entrypoint:
python -m ix_operator

Run the Rust crate tests:
cargo test -p ix_crypto

Long-term result

When complete, IX-Operator should be a serious, self-hosted operator platform
for autonomous agents that can:

• launch agents under one runtime

• establish authenticated sessions correctly

• move messages through a clear transport layer

• keep cryptographic responsibilities contained and auditable

• remain understandable to other engineers reading the code

That is the bar.
