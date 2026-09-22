#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path


ADMIN_ROOT = Path(__file__).resolve().parent.parent
CHALLENGE_ROOT = ADMIN_ROOT.parent
PUBLIC_ROOT = CHALLENGE_ROOT / "for_user"
KUBERNETES_ROOT = ADMIN_ROOT / "kubernetes"
SOLUTION_README = ADMIN_ROOT / "solution" / "README.md"
CTFD_DESCRIPTION = CHALLENGE_ROOT / "CTFD_DESCRIPTION.md"
ACCEPTANCE = ADMIN_ROOT / "ACCEPTANCE.md"
SERVICE_ROOTFS = ADMIN_ROOT / "service" / "rootfs.cpio.gz"
SERVICE_RUN_QEMU = ADMIN_ROOT / "service" / "run-qemu.sh"
MAX_GITHUB_BYTES = 100_000_000
MAX_EXPANDED_BYTES = 256 * 1024 * 1024

EXPECTED_HASHES = {
    PUBLIC_ROOT / "reclaim-box-000-player.tar.gz":
        "e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66",
    ADMIN_ROOT / "service" / "bzImage":
        "c71f589dc3e84c00006821cb60869e59c452e03300ae9dd045fd218fb525feb8",
    SERVICE_ROOTFS:
        "87c508c6e459102a60f6899c946c76c6209df8ace6fdefd92548788ea48dc7b3",
    ADMIN_ROOT / "solution" / "exploit.c":
        "bdc9c35fb7866a788a11cfc5fed5aaefed0105c3e4ce918134775089d729536b",
    ADMIN_ROOT / "solution" / "reclaim_v4_uapi.h":
        "74745a594a07fbe3abf3acc87ce13e6bd58b15e95395e5d849783cb05d3d2017",
    ADMIN_ROOT / "solution" / "exploit":
        "4bf27c63ccf36a28e586765d7fcadf7617ce227425538be32bf3966dc298301d",
}

REQUIRED_FILES = {
    CHALLENGE_ROOT / "README.md",
    CTFD_DESCRIPTION,
    PUBLIC_ROOT / "README.md",
    PUBLIC_ROOT / "SHA256SUMS",
    ADMIN_ROOT / "README.md",
    ADMIN_ROOT / ".env.example",
    ADMIN_ROOT / ".gitignore",
    ADMIN_ROOT / "Makefile",
    ADMIN_ROOT / "docker-compose.yaml",
    ACCEPTANCE,
    SOLUTION_README,
    ADMIN_ROOT / "solution" / "writeup.md",
    ADMIN_ROOT / "solution" / "Makefile",
    ADMIN_ROOT / "solution" / "solve_remote.py",
}

STALE_DOCUMENTATION_PATTERNS = {
    "legacy eight-instance capacity": re.compile(
        r"(?i)(?:\b8\s*(?:VMs?|s" r"lots?)\b|8\s*슬롯|전역\s*용량[^\n]{0,24}\b8\b)"
    ),
    "legacy logical-CPU host requirement": re.compile(r"(?i)\b8" r"0\s*vCPU\b"),
    "legacy five-run Route 2 result": re.compile(r"(?i)cold\s+boot\s+5" r"/5"),
    "legacy Route 2 timing range": re.compile(r"68\s*(?:~|～|-)\s*1" r"00\s*초"),
}

REQUIRED_DOCUMENTATION_SNIPPETS = {
    CTFD_DESCRIPTION: (
        "pwnable2.roomescapectf2026.site",
        "for_user/reclaim-box-000-player.tar.gz",
        "/settings",
        "같은 팀",
        "900초",
    ),
    ACCEPTANCE: (
        "t2d-standard-60",
        "Route 2 cold 30-way batch 3",
        "30/30",
        "TCP/31337 방화벽 개방",
    ),
}

TOKEN_PATTERNS = {
    "GitHub token": re.compile(
        rb"(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255})"
    ),
    "CTFd-prefixed token": re.compile(rb"(?i)\bctfd_[A-Za-z0-9_-]{20,512}\b"),
    "literal Authorization token": re.compile(
        rb"(?i)Authorization:\s*Token\s+(?![<$\[{])[-A-Za-z0-9._~+/=]{16,512}"
    ),
}


class AuditFailure(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_flag() -> bytes:
    try:
        text = SOLUTION_README.read_text(encoding="utf-8")
    except OSError as error:
        raise AuditFailure("solution/README.md is missing") from error
    matches = re.findall(r"(?m)^- Flag: `([^`\r\n]+)`\s*$", text)
    if len(matches) != 1:
        raise AuditFailure("solution/README.md must contain exactly one '- Flag: `...`' line")
    value = matches[0].encode("utf-8")
    if not re.fullmatch(rb"[A-Z][A-Z0-9_:.-]{1,31}\{[^\r\n{}]{8,256}\}", value):
        raise AuditFailure("the solution flag has an unexpected format")
    return value


def inspect_tokens(label: str, data: bytes, failures: list[str]) -> None:
    for description, pattern in TOKEN_PATTERNS.items():
        if pattern.search(data):
            failures.append(f"{description} material found in {label}")


def inspect_public_blob(
    label: str,
    data: bytes,
    flag: bytes,
    failures: list[str],
    *,
    depth: int = 0,
) -> None:
    if flag in data:
        failures.append(f"canonical flag found in public payload {label}")
    inspect_tokens(label, data, failures)
    if depth >= 5:
        return

    # tarfile handles plain tar and compressed tar streams. Bound each member
    # before extraction and recurse without writing attacker-controlled paths.
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                if member.size > MAX_EXPANDED_BYTES:
                    failures.append(f"oversized archive member {label}!{member.name}")
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                inspect_public_blob(
                    f"{label}!{member.name}", stream.read(MAX_EXPANDED_BYTES + 1),
                    flag, failures, depth=depth + 1,
                )
            return
    except (tarfile.TarError, EOFError, OSError):
        pass

    if data.startswith(b"\x1f\x8b"):
        try:
            expanded = gzip.decompress(data)
        except (gzip.BadGzipFile, EOFError, OSError):
            failures.append(f"invalid gzip payload {label}")
            return
        if len(expanded) > MAX_EXPANDED_BYTES:
            failures.append(f"oversized expanded gzip payload {label}")
            return
        inspect_public_blob(label + "!gunzip", expanded, flag, failures, depth=depth + 1)
        return

    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if info.file_size > MAX_EXPANDED_BYTES:
                        failures.append(f"oversized zip member {label}!{info.filename}")
                        continue
                    inspect_public_blob(
                        f"{label}!{info.filename}", archive.read(info), flag, failures,
                        depth=depth + 1,
                    )
        except (zipfile.BadZipFile, OSError):
            failures.append(f"invalid zip payload {label}")


def index_modes() -> tuple[Path | None, dict[Path, int]]:
    result = subprocess.run(
        ["git", "-C", str(CHALLENGE_ROOT), "rev-parse", "--show-toplevel"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return None, {}
    repo = Path(result.stdout.strip()).resolve()
    listing = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--stage", "--", str(CHALLENGE_ROOT)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    modes: dict[Path, int] = {}
    for line in listing.stdout.splitlines():
        metadata, name = line.split("\t", 1)
        mode = int(metadata.split()[0], 8)
        modes[(repo / name).resolve()] = mode
    return repo, modes


def release_files() -> list[Path]:
    files: list[Path] = []
    for path in CHALLENGE_ROOT.rglob("*"):
        relative = path.relative_to(CHALLENGE_ROOT)
        parts = relative.parts
        if ".runtime" in parts or "__pycache__" in parts:
            continue
        if parts[:3] == ("for_admin", "kubernetes", "build"):
            continue
        if relative in {
            Path("for_admin/.env"),
            Path("for_admin/solution/exploit.rebuilt"),
        }:
            continue
        if path.is_file() or path.is_symlink():
            files.append(path)
    return sorted(files)


def main() -> int:
    failures: list[str] = []
    flag = canonical_flag()

    for path in sorted(REQUIRED_FILES):
        if not path.is_file():
            failures.append(f"required file missing: {path.relative_to(CHALLENGE_ROOT)}")

    for path in sorted(CHALLENGE_ROOT.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(CHALLENGE_ROOT)
        for description, pattern in STALE_DOCUMENTATION_PATTERNS.items():
            if pattern.search(text):
                failures.append(f"{description} remains in {relative}")

    for path, snippets in REQUIRED_DOCUMENTATION_SNIPPETS.items():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet not in text:
                failures.append(
                    f"required documentation marker {snippet!r} missing from "
                    f"{path.relative_to(CHALLENGE_ROOT)}"
                )

    files = release_files()
    if not files:
        failures.append("challenge tree is empty")
    max_size = 0
    for path in files:
        relative = path.relative_to(CHALLENGE_ROOT)
        if path.is_symlink():
            failures.append(f"symbolic links are not allowed: {relative}")
            continue
        size = path.stat().st_size
        max_size = max(max_size, size)
        if size >= MAX_GITHUB_BYTES:
            failures.append(f"GitHub 100 MB limit exceeded: {relative}")
        if path.name in {".env", "deployment.json", "k3s.yaml", "values-production.json"}:
            failures.append(f"runtime configuration must not be committed: {relative}")
        if path.suffix.lower() in {".key", ".pem", ".p12", ".kubeconfig"}:
            failures.append(f"credential-like file must not be committed: {relative}")
        data = path.read_bytes()
        inspect_tokens(str(relative), data, failures)
        if flag in data and path != SOLUTION_README:
            failures.append(f"canonical flag appears outside solution/README.md: {relative}")

    for path, expected in EXPECTED_HASHES.items():
        if not path.is_file():
            failures.append(f"hashed artifact is missing: {path.relative_to(CHALLENGE_ROOT)}")
        elif sha256(path) != expected:
            failures.append(f"artifact hash mismatch: {path.relative_to(CHALLENGE_ROOT)}")

    try:
        expanded_rootfs = gzip.decompress(SERVICE_ROOTFS.read_bytes())
    except (OSError, EOFError, gzip.BadGzipFile) as error:
        raise AuditFailure("service/rootfs.cpio.gz is invalid") from error
    if flag not in expanded_rootfs:
        failures.append("service rootfs does not contain the canonical flag")
    if expanded_rootfs.count(b"reclaim.console_noecho=1") != 1:
        failures.append("service rootfs must contain exactly one private console marker")
    if expanded_rootfs.count(b"stty -echo") != 1:
        failures.append("service rootfs must contain exactly one conditional echo disable")

    try:
        run_qemu = SERVICE_RUN_QEMU.read_text(encoding="utf-8")
    except OSError as error:
        raise AuditFailure("service/run-qemu.sh is missing") from error
    if run_qemu.count("reclaim.console_noecho=1") != 1:
        failures.append("service/run-qemu.sh must append the private console marker exactly once")

    for path in sorted(path for path in PUBLIC_ROOT.rglob("*") if path.is_file()):
        inspect_public_blob(
            str(path.relative_to(CHALLENGE_ROOT)), path.read_bytes(), flag, failures
        )
    for path in sorted(path for path in KUBERNETES_ROOT.rglob("*") if path.is_file()):
        inspect_public_blob(
            str(path.relative_to(CHALLENGE_ROOT)), path.read_bytes(), flag, failures
        )

    _, modes = index_modes()
    for path, mode in modes.items():
        if not path.is_file() or not path.is_relative_to(CHALLENGE_ROOT):
            continue
        relative = path.relative_to(CHALLENGE_ROOT)
        if ".runtime" in relative.parts or relative == Path("for_admin/.env"):
            failures.append(f"runtime material is tracked by Git: {relative}")
        data = path.read_bytes()[:4]
        should_execute = data.startswith(b"#!") or data.startswith(b"\x7fELF")
        is_executable = mode == 0o100755
        if should_execute != is_executable:
            wanted = "100755" if should_execute else "100644"
            failures.append(f"Git index mode for {relative} must be {wanted}")

    expected_public_sum = (
        "e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66"
        "  reclaim-box-000-player.tar.gz\n"
    )
    sums_path = PUBLIC_ROOT / "SHA256SUMS"
    if sums_path.is_file() and sums_path.read_text(encoding="ascii") != expected_public_sum:
        failures.append("for_user/SHA256SUMS is not canonical")

    if failures:
        for failure in failures:
            print(f"audit error: {failure}", file=__import__("sys").stderr)
        raise SystemExit(f"release audit failed with {len(failures)} error(s)")

    print(
        "[RECLAIM-Q2-RELEASE-AUDIT-PASS] "
        f"files={len(files)} public_flag_leaks=0 token_leaks=0 max_file_bytes={max_size}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditFailure as error:
        raise SystemExit(f"release audit failed: {error}") from None
