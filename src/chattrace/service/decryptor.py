"""M2 DecryptService: turn a validated 32-byte WeChat 4.x master key into plaintext
SQLite copies under the per-account working tree.

Each encrypted DB derives its own page key from its own file-header salt:
    enc_key = PBKDF2-HMAC-SHA512(master_key, salt=head[0:16], 256000 iters, 32 bytes)
Every 4096-byte page is CBC-encrypted: AES(key, iv=page[-80-16 : -80]) over page[0:-80],
with the leading 16 magic bytes and trailing 80-byte reserve written through verbatim.

Output mirrors the source layout so query layers treat it like a normal db_storage tree:
    <account>/decrypted/<subdir>/<name>.db   (subdir ∈ contact|session|message|…)
Incremental: a target whose size equals the source and whose mtime is not older is skipped.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from Cryptodome.Cipher import AES

PAGE = 4096
RESERVE = 80
SQLITE_MAGIC = b"SQLite format 3\x00"
PBKDF2_ITERATIONS = 256000

ProgressCallback = Callable[[str, str, str], None]  # (phase, db_name, detail)

# Role precedence for ordering the discovered DB list (contact/session first, then
# message shards by numeric suffix, then auxiliary message DBs last).
_ROLE_RANK = {"contact": 0, "session": 1, "message": 2, "message_resource": 3}
_NUM_RE = re.compile(r"(\d+)")


class DecryptError(RuntimeError):
    pass


def _numeric_key(name: str) -> tuple:
    def convert(part: str) -> tuple:
        return (int(part), "") if part.isdigit() else (10**9, part)

    return tuple(convert(part) for part in _NUM_RE.split(name))


def _sort_key(db_path: Path) -> tuple:
    role = db_path.parent.name
    rank = _ROLE_RANK.get(role, 9)
    return (rank, _numeric_key(db_path.name))


def discover_source_dbs(db_storage: Path) -> list[Path]:
    """All WeChat 4.x DBs under db_storage (recursive, role-prioritised)."""
    if not db_storage.is_dir():
        raise DecryptError(f"db_storage not found: {db_storage}")
    found = [p for p in db_storage.rglob("*.db") if p.is_file()]
    if not found:
        raise DecryptError(f"no .db files under {db_storage}")
    # Drop in-progress / temp files (e.g. -wal/-journal are non-.db; some variants name
    # hot copies *.db.tmp).
    found = [p for p in found if not p.name.endswith(".tmp")]
    return sorted(found, key=_sort_key)


def enc_key_for(db_path: Path, master_key: bytes) -> bytes:
    with open(db_path, "rb") as fp:
        salt = fp.read(16)
    if len(salt) != 16:
        raise DecryptError(f"cannot read header salt from {db_path}")
    return hashlib.pbkdf2_hmac("sha512", master_key, salt, PBKDF2_ITERATIONS, dklen=32)


def _decrypt_page(page: bytes, key: bytes) -> bytes:
    iv = page[-RESERVE : -RESERVE + 16]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(page[:-RESERVE])


def decrypt_file(src: Path, dst: Path, master_key: bytes) -> None:
    """Stream-decrypt src into dst (atomic replace). Length-preserving."""
    key = enc_key_for(src, master_key)
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(dst.parent), prefix=".dec-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f_out, open(src, "rb") as f_in:
            header = f_in.read(PAGE)
            if len(header) < PAGE:
                raise DecryptError(f"source too small to be a SQLCipher page: {src}")
            # first page: [16B salt][4000B ciphertext][80B reserve]; page key derived
            # from the salt. Non-first pages have no salt, only ciphertext + reserve.
            f_out.write(SQLITE_MAGIC)
            f_out.write(_decrypt_page(header[16:], key))
            f_out.write(header[-RESERVE:])
            while True:
                page = f_in.read(PAGE)
                if not page:
                    break
                if len(page) != PAGE:
                    raise DecryptError(f"truncated page in {src}")
                f_out.write(_decrypt_page(page, key))
                f_out.write(page[-RESERVE:])
        os.replace(tmp_path, dst)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def smoke_test(db_path: Path) -> int:
    """Return sqlite_master object count; raise DecryptError when not a valid DB."""
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = con.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            return int(row[0]) if row else 0
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise DecryptError(f"decrypted DB failed smoke test: {db_path.name}: {exc}") from exc


@dataclass(frozen=True)
class DecryptPlanItem:
    src: Path
    dst: Path
    stale: bool          # True when dst is missing or older/shorter than src
    size: int


@dataclass
class DecryptReport:
    account_id: str
    discovered: int = 0
    decrypted: int = 0
    skipped: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)
    out_root: Path | None = None

    @property
    def ok(self) -> bool:
        return not self.failed and self.discovered > 0


def plan_decrypt(src_dbs: list[Path], db_storage_root: Path, out_db_storage: Path) -> list[DecryptPlanItem]:
    items: list[DecryptPlanItem] = []
    root = Path(db_storage_root)
    for src in src_dbs:
        dst = out_db_storage / src.relative_to(root)
        stale = True
        try:
            if dst.exists() and dst.stat().st_size == src.stat().st_size:
                if dst.stat().st_mtime >= src.stat().st_mtime:
                    stale = False
        except OSError:
            stale = True
        items.append(
            DecryptPlanItem(src=src, dst=dst, stale=stale, size=src.stat().st_size)
        )
    return items


def _db_storage_root_of(db_path: Path) -> Path:
    """Locate the db_storage ancestor of an arbitrary discovered DB path."""
    for parent in db_path.parents:
        if parent.name == "db_storage":
            return parent
    return db_path.parent.parent  # fallback: keep two levels under caller root


class DecryptService:
    """High-level orchestrator bound to one account + master key."""

    def __init__(self, db_storage: Path, master_key: bytes, out_db_storage: Path) -> None:
        self.db_storage = Path(db_storage)
        self.master_key = bytes(master_key)
        self.out_db_storage = Path(out_db_storage)

    def source_dbs(self) -> list[Path]:
        return discover_source_dbs(self.db_storage)

    def status(self) -> dict:
        """Per-DB readiness snapshot for UI (no key required)."""
        rows: list[dict] = []
        try:
            sources = self.source_dbs()
        except DecryptError:
            return {"dbs": [], "ready": 0, "total": 0, "error": "db_storage missing"}
        ready = 0
        for item in plan_decrypt(sources, self.db_storage, self.out_db_storage):
            rows.append(
                {
                    "name": str(item.src.relative_to(self.db_storage)).replace("\\", "/"),
                    "size": item.size,
                    "ready": not item.stale,
                }
            )
            ready += 0 if item.stale else 1
        return {"dbs": rows, "ready": ready, "total": len(rows)}

    def run(
        self,
        progress: ProgressCallback | None = None,
        incremental: bool = True,
    ) -> DecryptReport:
        sources = self.source_dbs()
        out_root = self.out_db_storage
        out_root.mkdir(parents=True, exist_ok=True)
        report = DecryptReport(account_id=self.out_db_storage.parent.parent.name, out_root=out_root)
        report.discovered = len(sources)
        plan = plan_decrypt(sources, self.db_storage, out_root)
        for item in plan:
            name = str(item.src.relative_to(self.db_storage)).replace("\\", "/")
            if incremental and not item.stale:
                report.skipped += 1
                if progress:
                    progress("skip", name, f"{item.size / 1e6:.1f}MB")
                continue
            if progress:
                progress("decrypt", name, "")
            try:
                decrypt_file(item.src, item.dst, self.master_key)
                smoke_test(item.dst)
                report.decrypted += 1
                if progress:
                    progress("ok", name, f"{item.size / 1e6:.1f}MB")
            except (DecryptError, OSError, sqlite3.Error) as exc:
                report.failed.append((name, str(exc)))
                if progress:
                    progress("fail", name, str(exc))
        return report

    def verify(self) -> bool:
        """Re-smoke-test every currently ready output DB."""
        ok_all = True
        for db in sorted(self.out_db_storage.rglob("*.db")):
            try:
                smoke_test(db)
            except DecryptError:
                ok_all = False
        return ok_all
