#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import tarfile
from pathlib import Path


PREFIX = "q2-reclaim-kubernetes"
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "build",
}


def included(path: Path) -> bool:
    if any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    if path.suffix in {".pyc", ".pyo"}:
        return False
    return path.is_file()


def executable(path: Path) -> bool:
    return path.suffix == ".sh" or path.name in {
        "audit-rendered.py",
        "package-reference.py",
        "check_client.py",
        "verify_live.py",
        "audit_live_objects.py",
        "real_client_smoke.py",
        "test_ctfd_compat.py",
        "test_redis_state.py",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--flag-file", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    paths = sorted(
        (path for path in source.rglob("*") if included(path)),
        key=lambda item: item.relative_to(source).as_posix(),
    )
    if not paths:
        raise SystemExit("no Kubernetes reference files found")

    secret = b""
    if args.flag_file and args.flag_file.is_file():
        secret = args.flag_file.read_bytes().strip()
    for path in paths:
        data = path.read_bytes()
        if secret and secret in data:
            raise SystemExit("canonical flag bytes appear in Kubernetes reference source")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + f".tmp-{os.getpid()}")
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    directories = {Path(PREFIX)}
                    for path in paths:
                        relative = path.relative_to(source)
                        current = Path(PREFIX)
                        for part in relative.parts[:-1]:
                            current /= part
                            directories.add(current)
                    for directory in sorted(directories, key=lambda item: item.as_posix()):
                        info = tarfile.TarInfo(directory.as_posix() + "/")
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        info.uid = info.gid = 0
                        info.uname = info.gname = "root"
                        info.mtime = 0
                        archive.addfile(info)
                    for path in paths:
                        data = path.read_bytes()
                        name = (Path(PREFIX) / path.relative_to(source)).as_posix()
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o755 if executable(path) else 0o644
                        info.uid = info.gid = 0
                        info.uname = info.gname = "root"
                        info.mtime = 0
                        archive.addfile(info, io.BytesIO(data))
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"files={len(paths)}")
    print(f"sha256={digest}")
    print("flag_leaks=0")
    print("[KUBERNETES-REFERENCE-PACKAGE-PASS]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
