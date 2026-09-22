#!/usr/bin/env python3
"""Audit a v4 player initramfs without printing secret bytes or object names."""

from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile


HEX_OBJECT = re.compile(r"[0-9a-f]{32}")
PRIVATE_PATH_WORDS = (
    "organizer",
    "exploit",
    "release-a",
    "release-e",
    "release-contract",
    "proof",
    "private",
    "manifest",
    "reclaim_v4_uapi",
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--expected-flag-file", type=Path)
    parser.add_argument(
        "--require-console-noecho", action="store_true",
        help="require the private TCP serial console echo guard",
    )
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def align4(value: int) -> int:
    return (value + 3) & ~3


def parse_newc(data: bytes) -> dict[str, tuple[int, int, int, bytes]]:
    entries: dict[str, tuple[int, int, int, bytes]] = {}
    offset = 0
    while True:
        require(offset + 110 <= len(data), "truncated newc header")
        header = data[offset : offset + 110]
        require(header[:6] == b"070701", "unexpected cpio format")
        fields = [int(header[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        mode, uid, gid = fields[1], fields[2], fields[3]
        size, namesize = fields[6], fields[11]
        offset += 110
        require(namesize > 0 and offset + namesize <= len(data), "bad cpio name")
        raw_name = data[offset : offset + namesize]
        require(raw_name[-1:] == b"\0", "unterminated cpio name")
        name = raw_name[:-1].decode("utf-8")
        offset = align4(offset + namesize)
        require(offset + size <= len(data), "truncated cpio body")
        body = data[offset : offset + size]
        offset = align4(offset + size)
        if name == "TRAILER!!!":
            break
        normalized = name.removeprefix("./").rstrip("/")
        if normalized in ("", "."):
            continue
        pure = PurePosixPath(normalized)
        require(not pure.is_absolute() and ".." not in pure.parts, "unsafe cpio path")
        require(normalized not in entries, "duplicate cpio entry")
        entries[normalized] = (mode, uid, gid, body)
    return entries


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_expected_flag(path: Path | None) -> bytes:
    if path is None:
        return b"SHA{test}\n"
    require(path.is_file() and not path.is_symlink(), "missing expected flag input")
    data = path.read_bytes()
    require(b"\0" not in data, "expected flag is not text")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("expected flag is not UTF-8") from error
    line = text.rstrip("\r\n")
    require(
        bool(line) and "\r" not in line and "\n" not in line,
        "expected flag must contain one non-empty line",
    )
    return line.encode("utf-8") + b"\n"


def main() -> int:
    args = arguments()
    for path in (args.rootfs, args.kernel):
        require(path.is_file() and not path.is_symlink(), f"missing input: {path}")
    expected_flag = normalized_expected_flag(args.expected_flag_file)
    compressed = args.rootfs.read_bytes()
    entries = parse_newc(gzip.decompress(compressed))

    for required in (
        "init",
        "reclaim.ko",
        "usr/bin/reclaim-approval",
        "etc/passwd",
        "etc/group",
        "root/quarantine/000",
    ):
        require(required in entries, f"missing player entry: {required}")
    lowered = [name.lower() for name in entries]
    require(
        not any(word in name for name in lowered for word in PRIVATE_PATH_WORDS),
        "private/organizer path leaked into player rootfs",
    )
    require("usr/include/reclaim_uapi.h" not in entries, "solution-shaped UAPI leaked")
    require("gate/approval.token" not in entries, "legacy approval token leaked")

    setid = []
    for name, (mode, uid, gid, _) in entries.items():
        if stat.S_ISREG(mode) and stat.S_IMODE(mode) & 0o6000:
            setid.append((name, stat.S_IMODE(mode), uid, gid))
    require(
        setid == [("usr/bin/reclaim-approval", 0o4755, 0, 0)],
        f"unexpected setid surface: {setid!r}",
    )
    module_mode, module_uid, module_gid, module = entries["reclaim.ko"]
    require(
        stat.S_ISREG(module_mode)
        and stat.S_IMODE(module_mode) == 0o600
        and (module_uid, module_gid) == (0, 0),
        "module ownership/mode mismatch",
    )
    root_mode, root_uid, root_gid, _ = entries["root"]
    vault_mode, vault_uid, vault_gid, _ = entries["root/quarantine/000"]
    require(
        stat.S_ISDIR(root_mode)
        and stat.S_IMODE(root_mode) == 0o700
        and (root_uid, root_gid) == (0, 0),
        "root directory contract mismatch",
    )
    require(
        stat.S_ISDIR(vault_mode)
        and stat.S_IMODE(vault_mode) == 0o700
        and (vault_uid, vault_gid) == (0, 0),
        "vault directory contract mismatch",
    )

    prefix = "root/quarantine/000/"
    objects = [
        (name, meta) for name, meta in entries.items() if name.startswith(prefix)
    ]
    require(len(objects) == 128, "vault object count mismatch")
    flags = 0
    for name, (mode, uid, gid, body) in objects:
        require(
            HEX_OBJECT.fullmatch(name[len(prefix) :]) is not None,
            "vault filename grammar mismatch",
        )
        require(
            stat.S_ISREG(mode)
            and stat.S_IMODE(mode) == 0o400
            and (uid, gid) == (0, 0),
            "vault object ownership/mode mismatch",
        )
        if body == expected_flag:
            flags += 1
        else:
            require(expected_flag.rstrip(b"\n") not in body,
                    "deployment flag duplicated in a decoy")
    require(flags == 1, "flag object cardinality mismatch")

    init = entries["init"][3]
    require(
        b"release-a" not in init
        and b"release-e" not in init
        and b"organizer" not in init,
        "organizer branch leaked into player init",
    )
    require(
        b"/dev/reclaim-evidence" in init and b"chmod 0400" in init,
        "evidence DAC setup missing",
    )
    noecho_marker = init.count(b"reclaim.console_noecho=1")
    noecho_action = init.count(b"stty -echo")
    if args.require_console_noecho:
        require(
            noecho_marker == 1 and noecho_action == 1,
            "TCP serial console echo guard missing",
        )
    else:
        require(
            (noecho_marker, noecho_action) in ((0, 0), (1, 1)),
            "partial TCP serial console echo guard",
        )

    with tempfile.TemporaryDirectory(prefix="reclaim-v4-audit.") as temporary:
        module_path = Path(temporary) / "reclaim.ko"
        gate_path = Path(temporary) / "reclaim-approval"
        module_path.write_bytes(module)
        gate_path.write_bytes(entries["usr/bin/reclaim-approval"][3])
        sections = subprocess.run(
            ["readelf", "-SW", str(module_path)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        require(".debug_" not in sections, "module debug section survived")
        symbols = subprocess.run(
            ["nm", "-a", str(module_path)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        allowed = {
            ".text",
            ".init.text",
            ".exit.text",
            "init_module",
            "cleanup_module",
            "__pfx_init_module",
            "__pfx_cleanup_module",
        }
        for line in symbols:
            fields = line.split()
            if len(fields) >= 3 and fields[-2] in ("t", "T"):
                require(fields[-1] in allowed, "named internal module text survived")
        literals = subprocess.run(
            ["strings", "-a", str(module_path)],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        for forbidden in (
            b"/dev/reclaim-archive",
            b"reclaim-work",
            b"commit_creds",
            b"prepare_kernel_cred",
            b"modprobe_path",
            b"core_pattern",
        ):
            require(forbidden not in literals, "forbidden shortcut literal survived")
        gate_file = subprocess.run(
            ["file", str(gate_path)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        require("statically linked" in gate_file and "stripped" in gate_file,
                "player gate is not static+stripped")
        gate_symbols = subprocess.run(
            ["nm", "-a", str(gate_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ).stdout
        require(" no symbols" in gate_symbols, "player gate symbols survived")

    print(
        "[V4-PLAYER-ARTIFACT-AUDIT-PASS] files="
        f"{len(entries)} vault_objects=128 flag_objects=1 setuid_files=1 "
        "private_paths=0 uapi=0 module_symbols=0 gate_symbols=0"
    )
    print(f"kernel_sha256={sha256(args.kernel.read_bytes())}")
    print(f"module_sha256={sha256(module)}")
    print(f"rootfs_sha256={sha256(compressed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
