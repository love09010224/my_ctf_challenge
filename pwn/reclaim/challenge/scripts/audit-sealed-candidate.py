#!/usr/bin/env python3
"""Audit only what a player receives in the sealed v4 candidate.

This is an artifact-hygiene and leakage regression check.  It deliberately
does not claim that a clean/stripped artifact is difficult; the independent
blind solve remains the difficulty oracle.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


EXPECTED_MEMBERS = {
    "README.md": 0o444,
    "bzImage": 0o444,
    "rootfs.cpio.gz": 0o444,
    "run.sh": 0o555,
}
EXPECTED_MTIME = 1767225600  # 2026-01-01 00:00:00 UTC

README_FORBIDDEN = re.compile(
    rb"ghost|use[- ]after[- ]free|\buaf\b|\bpipe\b|xattr|inotify|"
    rb"\bslab\b|\bheap\b|\brace\b|bookmark|snapshot|codec|ledger|"
    rb"organizer|exploit|intended",
    re.IGNORECASE,
)

MODULE_FORBIDDEN = (
    b"/dev/reclaim-archive",
    b"reclaim-work",
    b"commit_creds",
    b"prepare_kernel_cred",
    b"call_usermodehelper",
    b"modprobe_path",
    b"core_pattern",
    b"ghost",
    b"use-after-free",
    b"inotify",
    b"xattr",
    b"pipe_buffer",
)

FORBIDDEN_IMPORTS = {
    "commit_creds",
    "prepare_kernel_cred",
    "call_usermodehelper",
    "call_usermodehelper_exec",
    "modprobe_path",
    "core_pattern",
}

REQUIRED_CONFIG = (
    "# CONFIG_KALLSYMS is not set",
    "# CONFIG_KPROBES is not set",
    "# CONFIG_IKCONFIG is not set",
    "CONFIG_DEBUG_INFO_NONE=y",
    "CONFIG_STATIC_USERMODEHELPER=y",
    'CONFIG_STATIC_USERMODEHELPER_PATH=""',
    "# CONFIG_USER_NS is not set",
    "# CONFIG_BPF_SYSCALL is not set",
    "# CONFIG_IO_URING is not set",
    "# CONFIG_RANDOM_KMALLOC_CACHES is not set",
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--extract-vmlinux", required=True, type=Path)
    parser.add_argument("--kernel-config", required=True, type=Path)
    parser.add_argument(
        "--player-audit",
        type=Path,
        default=Path(__file__).with_name("audit-player-candidate.py"),
    )
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def run(*command: str, input_data: bytes | None = None) -> bytes:
    return subprocess.run(
        command,
        input=input_data,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def load_player_audit(path: Path):
    spec = importlib.util.spec_from_file_location("reclaim_player_audit", path)
    require(spec is not None and spec.loader is not None,
            "could not load player audit helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    args = arguments()
    for path in (
        args.bundle,
        args.extract_vmlinux,
        args.kernel_config,
        args.player_audit,
    ):
        require(path.is_file() and not path.is_symlink(), f"missing input: {path}")

    bodies: dict[str, bytes] = {}
    with tarfile.open(args.bundle, "r:gz") as archive:
        members = archive.getmembers()
        require({member.name for member in members} == set(EXPECTED_MEMBERS),
                "sealed top-level member set mismatch")
        require(len(members) == len(EXPECTED_MEMBERS),
                "duplicate sealed top-level member")
        for member in members:
            require(member.isfile() and not member.issym() and not member.islnk(),
                    f"non-regular sealed member: {member.name}")
            require(member.mode == EXPECTED_MEMBERS[member.name],
                    f"sealed mode mismatch: {member.name}: {member.mode:o}")
            require((member.uid, member.gid) == (0, 0),
                    f"sealed ownership mismatch: {member.name}")
            require(member.mtime == EXPECTED_MTIME,
                    f"sealed mtime mismatch: {member.name}")
            stream = archive.extractfile(member)
            require(stream is not None, f"could not read sealed member: {member.name}")
            bodies[member.name] = stream.read()

    readme = bodies["README.md"]
    require(README_FORBIDDEN.search(readme) is None,
            "solution-shaped wording survived in README")
    require(b"RE:CLAIM" in readme and b"./run.sh" in readme,
            "README title/run contract missing")

    launcher = bodies["run.sh"]
    for required in (
        b"qemu-system-x86_64",
        b"+smep,+smap",
        b"kaslr",
        b"pti=on",
        b"-net none",
        b"-monitor none",
        b"-no-reboot",
    ):
        require(required in launcher, f"launcher contract missing: {required!r}")
    for forbidden in (b"nokaslr", b"-s\n", b"-S\n", b"rdinit=", b"init=/bin/sh"):
        require(forbidden not in launcher,
                f"debug/bypass launcher option survived: {forbidden!r}")

    player = load_player_audit(args.player_audit)
    entries = player.parse_newc(gzip.decompress(bodies["rootfs.cpio.gz"]))
    require("reclaim.ko" in entries, "player module missing")
    module = entries["reclaim.ko"][3]
    require(not any(value in module for value in MODULE_FORBIDDEN),
            "solution/shortcut literal survived in player module")

    config_lines = set(args.kernel_config.read_text().splitlines())
    for required in REQUIRED_CONFIG:
        require(required in config_lines, f"kernel config contract missing: {required}")

    with tempfile.TemporaryDirectory(prefix="reclaim-v4-sealed-audit.") as temporary:
        temporary_path = Path(temporary)
        kernel_path = temporary_path / "bzImage"
        rootfs_path = temporary_path / "rootfs.cpio.gz"
        module_path = temporary_path / "reclaim.ko"
        payload_path = temporary_path / "vmlinux"
        kernel_path.write_bytes(bodies["bzImage"])
        rootfs_path.write_bytes(bodies["rootfs.cpio.gz"])
        module_path.write_bytes(module)

        # Reuse the deeper rootfs, gate, vault, and internal-text-symbol audit.
        subprocess.run(
            [
                "python3",
                str(args.player_audit),
                "--rootfs",
                str(rootfs_path),
                "--kernel",
                str(kernel_path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        with payload_path.open("wb") as output:
            subprocess.run(
                [str(args.extract_vmlinux), str(kernel_path)],
                check=True,
                stdout=output,
                stderr=subprocess.PIPE,
            )
        require(payload_path.stat().st_size > 0,
                "could not extract distributed kernel payload")
        sections = run("readelf", "-SW", str(payload_path))
        require(not re.search(rb"\.symtab|\.debug_|\.BTF|kallsyms", sections),
                "symbol/debug/kallsyms section survived in kernel payload")
        nm = subprocess.run(
            ["nm", "-a", str(payload_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(not nm.stdout.strip(), "ordinary kernel symbols survived")
        kernel_strings = run("strings", "-a", str(payload_path))
        require(not re.search(
            rb"(^|\n)kallsyms_(names|offsets|token_table)(\n|$)",
            kernel_strings,
        ), "compressed kallsyms database survived")

        symbols = run("readelf", "-Ws", str(module_path)).decode()
        imports: set[str] = set()
        internal_text: list[str] = []
        allowed_text = {
            ".text",
            ".init.text",
            ".exit.text",
            "init_module",
            "cleanup_module",
            "__pfx_init_module",
            "__pfx_cleanup_module",
        }
        for line in symbols.splitlines():
            fields = line.split()
            if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
                continue
            symbol_type, bind, index, name = fields[3], fields[4], fields[6], fields[7]
            if index == "UND" and name:
                imports.add(name)
            if index != "UND" and symbol_type == "FUNC" and name not in allowed_text:
                internal_text.append(name)
        require(not internal_text,
                f"named internal module text survived: {internal_text!r}")
        require(not (imports & FORBIDDEN_IMPORTS),
                f"terminal helper import survived: {sorted(imports & FORBIDDEN_IMPORTS)!r}")

    archive_hash = hashlib.sha256(args.bundle.read_bytes()).hexdigest()
    kernel_hash = hashlib.sha256(bodies["bzImage"]).hexdigest()
    rootfs_hash = hashlib.sha256(bodies["rootfs.cpio.gz"]).hexdigest()
    module_hash = hashlib.sha256(module).hexdigest()
    visible_native = sorted(
        name for name in imports
        if name.startswith("key_") or name.startswith("rb_")
    )
    print(
        "[V4-SEALED-SURFACE-AUDIT-PASS] members=4 modes=canonical "
        "kernel_symbols=0 module_internal_text=0 private_paths=0 "
        "terminal_imports=0"
    )
    print(f"bundle_sha256={archive_hash}")
    print(f"kernel_sha256={kernel_hash}")
    print(f"rootfs_sha256={rootfs_hash}")
    print(f"module_sha256={module_hash}")
    print("visible_native_imports=" + ",".join(visible_native))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
