#!/usr/bin/env python3
"""Freeze module-resident callback carriers relevant to a fake key_type audit."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess


EXPECTED_CALLBACKS = {
    "reclaim_evidence_read",
    "reclaim_codec_ioctl",
    "reclaim_ledger_llseek",
    "reclaim_ledger_read",
    "reclaim_ledger_ioctl",
    "reclaim_ledger_open",
    "reclaim_ledger_release",
    "reclaim_ledger_fsync",
    "reclaim_case_ioctl",
    "reclaim_case_open",
    "reclaim_case_release",
    "reclaim_receipt_ioctl",
    "reclaim_receipt_release",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    args = arguments()
    require(args.module.is_file(), "missing unstripped module")
    symbols_text = subprocess.run(
        ["nm", "-an", str(args.module)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    require(
        not any(name in symbols_text for name in ("reclaim_fold", "reclaim_mix", "reclaim_reduce")),
        "callable codec transform survived",
    )
    identity = re.search(
        r"^([0-9a-f]+)\s+([rR])\s+reclaim_codec_identity$",
        symbols_text,
        re.MULTILINE,
    )
    require(identity is not None, "module-local codec identity is not rodata")
    functions: dict[int, str] = {}
    for match in re.finditer(
        r"^([0-9a-f]+)\s+[tT]\s+(reclaim_[A-Za-z0-9_.]+)$",
        symbols_text,
        re.MULTILINE,
    ):
        name = match.group(2)
        if not name.startswith("reclaim_") or name.startswith("reclaim_v4_release_"):
            continue
        functions[int(match.group(1), 16)] = name

    relocations = subprocess.run(
        ["readelf", "-rW", str(args.module)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    section = re.search(
        r"Relocation section '\.rela\.rodata'.*?\n(.*?)(?=\nRelocation section|\Z)",
        relocations,
        re.DOTALL,
    )
    require(section is not None, "missing rodata relocations")
    observed = set()
    for match in re.finditer(r"\.text \+ ([0-9a-f]+)$", section.group(1), re.MULTILINE):
        address = int(match.group(1), 16)
        require(address in functions, f"unmapped rodata callback at text+0x{address:x}")
        observed.add(functions[address])
    require(observed == EXPECTED_CALLBACKS,
            f"module callback carrier set changed: {sorted(observed)!r}")

    config = args.config.read_text(encoding="utf-8").splitlines()
    require("CONFIG_STRICT_MODULE_RWX=y" in config, "strict module RWX disabled")
    print(
        "[V4-CODEC-CALLBACK-SURFACE-PASS] module_identity=rodata "
        f"callable_transforms=0 callback_carriers={len(observed)} strict_rwx=1"
    )
    print("callbacks=" + ",".join(sorted(observed)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
