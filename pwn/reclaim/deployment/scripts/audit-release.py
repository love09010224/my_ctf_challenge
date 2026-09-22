#!/usr/bin/env python3
"""Audit the post-event public source tree without printing matched secrets."""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    Path("challenge/module/reclaim_v4_release.c"): "cb1535aa0d7c24a6239ca03502addd5786f0ffa8c023f8e9b1a580e14dacd02f",
    Path("challenge/config/linux-6.12.103.config"): "ee880e5aea018b8185fdeeed6d6338a096b16ade3656d8bb3b867158d0dcc9c4",
    Path("solutions/route-2/exploit.c"): "bdc9c35fb7866a788a11cfc5fed5aaefed0105c3e4ce918134775089d729536b",
    Path("solutions/route-2/reclaim_v4_uapi.h"): "74745a594a07fbe3abf3acc87ce13e6bd58b15e95395e5d849783cb05d3d2017",
}
REQUIRED = (
    Path("README.md"), Path("CTFD_DESCRIPTION.md"), Path("handout/SHA256SUMS"),
    Path("challenge/README.md"), Path("solutions/route-1/writeup.md"),
    Path("solutions/route-2/writeup.md"), Path("deployment/ACCEPTANCE.md"),
    Path("docs/capacity-and-acceptance.md"), Path("artifacts/SHA256SUMS"),
)
PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})"),
    "CTFd bearer": re.compile(rb"\bctfd_[A-Za-z0-9_-]{20,}\b", re.I),
    "Google service account key": re.compile(rb'"private_key"\s*:\s*"-----BEGIN'),
}
ALLOW_NAMES = {".env.example"}

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def main() -> int:
    failures=[]
    for rel in REQUIRED:
        if not (ROOT/rel).is_file(): failures.append(f"missing required file: {rel}")
    for rel,expected in EXPECTED.items():
        p=ROOT/rel
        if not p.is_file() or digest(p)!=expected: failures.append(f"hash mismatch: {rel}")
    files=[]
    repo = Path(subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
        check=True, text=True, stdout=subprocess.PIPE,
    ).stdout.strip())
    tracked = subprocess.check_output(
        ["git", "-C", str(repo), "ls-files", "-z", "--", str(ROOT.relative_to(repo))]
    ).decode().split("\0")
    for name in sorted(name for name in tracked if name):
        p = repo / name
        if not p.is_file(): continue
        rel=p.relative_to(ROOT); files.append(p)
        if p.is_symlink(): failures.append(f"symlink not allowed: {rel}"); continue
        if p.stat().st_size >= 100_000_000: failures.append(f"GitHub file limit: {rel}")
        if p.name == '.env' or (p.suffix.lower() in {'.pem','.key','.p12','.kubeconfig'} and p.name not in ALLOW_NAMES):
            failures.append(f"credential-like file: {rel}")
        data=p.read_bytes()
        for name,rx in PATTERNS.items():
            if rx.search(data): failures.append(f"{name} material: {rel}")
    expected_sum='e7036d5a345960ad172bbab3dea5530ca718bf5f6936a24b8c9c1ffc2ee9fc66  reclaim-box-000-player.tar.gz\n'
    hp=ROOT/'handout/SHA256SUMS'
    if hp.is_file() and hp.read_text(encoding='ascii') != expected_sum:
        failures.append('handout/SHA256SUMS is not canonical')
    if failures:
        for item in failures: print('audit error:',item,file=sys.stderr)
        return 1
    result=subprocess.run(['git','-C',str(ROOT),'status','--porcelain'],stdout=subprocess.PIPE,text=True)
    print(f"[RECLAIM-PUBLICATION-AUDIT-PASS] files={len(files)} operational_secret_hits=0")
    return 0
if __name__=='__main__': raise SystemExit(main())
