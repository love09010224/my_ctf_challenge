#!/usr/bin/env python3
"""Populate box 000 with one text flag and random binary decoys.

The private manifest must live outside the rootfs tree and outside any public
distribution archive.  Filenames and approval tokens are generated afresh for
each invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat


NAME_BYTES = 16
NAME_LENGTH = NAME_BYTES * 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--flag-file", required=True, type=Path)
    parser.add_argument("--private-manifest", required=True, type=Path)
    parser.add_argument("--dummy-count", type=int, default=127)
    parser.add_argument("--dummy-min", type=int, default=128)
    parser.add_argument("--dummy-max", type=int, default=8192)
    parser.add_argument("--without-approval-token", action="store_true")
    return parser.parse_args()


def normalized_flag(path: Path) -> bytes:
    data = path.read_bytes()
    if b"\x00" in data:
        raise ValueError("flag must be text, not a NUL-containing blob")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("flag must be valid UTF-8 text") from error

    data = data.rstrip(b"\r\n")
    if not data or b"\n" in data or b"\r" in data:
        raise ValueError("flag must contain exactly one non-empty text line")
    if len(data) > 512:
        raise ValueError("flag line is unexpectedly large")
    return data + b"\n"


def unique_name(used: set[str]) -> str:
    while True:
        name = secrets.token_hex(NAME_BYTES)
        if name not in used:
            used.add(name)
            return name


def write_exclusive(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while populating vault")
            view = view[written:]
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def prepare_directory(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)


def main() -> int:
    args = parse_args()
    if args.dummy_count < 1 or args.dummy_count > 4096:
        raise SystemExit("dummy count must be between 1 and 4096")
    if not 1 <= args.dummy_min <= args.dummy_max <= 16 * 1024 * 1024:
        raise SystemExit("invalid dummy size range")

    flag = normalized_flag(args.flag_file)
    root = args.root.resolve()
    vault = root / "root" / "quarantine" / "000"
    prepare_directory(root / "root", 0o700)
    prepare_directory(root / "root" / "quarantine", 0o700)
    prepare_directory(vault, 0o700)

    existing = list(vault.iterdir())
    if existing:
        raise SystemExit(f"refusing to populate non-empty vault: {vault}")

    used: set[str] = set()
    flag_name = unique_name(used)
    write_exclusive(vault / flag_name, flag, 0o400)

    dummy_metadata: list[dict[str, object]] = []
    for _ in range(args.dummy_count):
        name = unique_name(used)
        size = args.dummy_min + secrets.randbelow(
            args.dummy_max - args.dummy_min + 1
        )
        data = secrets.token_bytes(size)
        write_exclusive(vault / name, data, 0o400)
        dummy_metadata.append(
            {
                "name": name,
                "size": size,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    args.private_manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": 1,
        "vault": str(vault.relative_to(root)),
        "filename_grammar": f"[0-9a-f]{{{NAME_LENGTH}}}",
        "flag_filename": flag_name,
        "flag_sha256": hashlib.sha256(flag).hexdigest(),
        "dummy_count": args.dummy_count,
        "dummies": dummy_metadata,
    }
    if not args.without_approval_token:
        gate_directory = root / "root" / "reclaim"
        prepare_directory(gate_directory, 0o700)
        approval_token = secrets.token_hex(32)
        write_exclusive(
            gate_directory / "approval.token",
            approval_token.encode("ascii") + b"\n",
            0o400,
        )
        manifest["approval_token"] = approval_token
    args.private_manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(args.private_manifest, stat.S_IRUSR | stat.S_IWUSR)

    print(
        f"populated box 000 with {args.dummy_count + 1} extensionless "
        f"hex-named objects; private mapping: {args.private_manifest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
