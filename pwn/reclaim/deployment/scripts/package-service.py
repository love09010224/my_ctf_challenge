#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import tarfile
from pathlib import Path


MEMBERS = (
    "Dockerfile",
    "README.md",
    "SHA256SUMS",
    "bzImage",
    "docker-compose.example.yml",
    "entrypoint.sh",
    "rootfs.cpio.gz",
    "run-qemu.sh",
    "service-contract.json",
)
EXECUTABLE = {"entrypoint.sh", "run-qemu.sh"}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def verify_checksums(source: Path) -> None:
    expected: dict[str, str] = {}
    for line in (source / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        checksum, name = line.split(None, 1)
        expected[name.lstrip(" *")] = checksum
    for name in ("bzImage", "rootfs.cpio.gz"):
        if expected.get(name) != digest(source / name):
            raise SystemExit(f"service checksum mismatch: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic private service bundle")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if output == source or source in output.parents:
        raise SystemExit("output must be outside the service source tree")
    for name in MEMBERS:
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"required regular service file is missing: {name}")
    verify_checksums(source)

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name in MEMBERS:
            data = (source / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o555 if name in EXECUTABLE else 0o444
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + f".tmp.{os.getpid()}")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as stream:
            stream.write(tar_buffer.getvalue())
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    print(f"[RECLAIM-Q2-SERVICE-BUNDLE-PASS] sha256={digest(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
