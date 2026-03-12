from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from ix_operator import PRODUCT_NAME, __version__
from ix_operator.app import OperatorApplication
from ix_operator.crypto import native_extension_available


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ix-operator")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("info", help="Show runtime and extension status")
    subparsers.add_parser("status", help="Show structured runtime status")

    identity_parser = subparsers.add_parser("identity", help="Manage node identity")
    identity_subparsers = identity_parser.add_subparsers(dest="identity_command")

    identity_init_parser = identity_subparsers.add_parser(
        "init",
        help="Create the local node identity if it does not exist",
    )
    identity_init_parser.add_argument("--peer-id", default=None)
    identity_init_parser.add_argument("--peer-id-prefix", default="node")

    identity_subparsers.add_parser("show", help="Show the current node identity")

    run_script_parser = subparsers.add_parser(
        "run-script",
        help="Boot a local node and execute an IX script file",
    )
    run_script_parser.add_argument("path")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(list(argv) if argv is not None else None)

    if parsed_args.command is None:
        parsed_args = parser.parse_args(["info"])

    app = OperatorApplication.from_env()

    if parsed_args.command == "info":
        snapshot = app.status_snapshot()
        print(
            f"{PRODUCT_NAME} v{__version__}\n"
            f"Mode: {app.config.mode.value}\n"
            f"Transport: {app.config.transport_backend.value}\n"
            f"Transport implemented: {snapshot.transport_supported}\n"
            f"Runtime root: {app.config.runtime_paths.root}\n"
            f"Boot ID: {app.context.boot_id}\n"
            f"Native extension available: {native_extension_available()}\n"
            f"Identity path: {app.identity_store.path}"
        )
        return 0

    if parsed_args.command == "status":
        snapshot = app.status_snapshot()
        print(
            f"{snapshot.product_name} v{snapshot.version}\n"
            f"Mode: {snapshot.mode}\n"
            f"Transport: {snapshot.transport}\n"
            f"Transport implemented: {snapshot.transport_supported}\n"
            f"Boot ID: {snapshot.boot_id}\n"
            f"Runtime root: {snapshot.runtime_root}\n"
            f"Audit log: {snapshot.audit_log_path}\n"
            f"Identity path: {snapshot.identity_path}\n"
            f"Identity exists: {snapshot.identity_exists}\n"
            f"Native extension available: {snapshot.native_extension_available}\n"
            f"Local peer ID: {snapshot.local_peer_id or 'none'}"
        )
        return 0

    if parsed_args.command == "identity":
        if parsed_args.identity_command == "init":
            identity = app.initialize_identity(
                peer_id=parsed_args.peer_id,
                peer_id_prefix=parsed_args.peer_id_prefix,
            )
            print(
                f"Identity initialized.\n"
                f"Peer ID: {identity.peer_id}\n"
                f"Path: {app.identity_store.path}"
            )
            return 0

        if parsed_args.identity_command == "show":
            identity = app.load_identity()
            if identity is None:
                print("No identity initialized.")
                return 1

            print(
                f"Peer ID: {identity.peer_id}\n"
                f"Signing public key: {identity.signing_public_key.hex()}\n"
                f"Exchange public key: {identity.exchange_public_key.hex()}\n"
                f"Path: {app.identity_store.path}"
            )
            return 0

        parser.error("identity requires a subcommand")
        return 2

    if parsed_args.command == "run-script":
        source = Path(parsed_args.path).read_text(encoding="utf-8")
        result = app.run_script(source)
        print(
            f"Script executed.\n"
            f"Peer ID: {result.peer_id}\n"
            f"Agent count: {result.report_count}\n"
            f"Agents: {', '.join(result.agent_ids)}"
        )
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
