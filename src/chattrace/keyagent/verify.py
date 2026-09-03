"""SQLCipher4/WCDB HMAC self-check and DB header probing (verified layout, 4.1.12.55)."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

PAGE_SIZE = 4096
RESERVE = 80
KDF_ITER = 256_000
HMAC_ITER = 2
HMAC_SIZE = 64

#: candidate (password, salt, endian) derivation variants we can validate against
#: Only "pbkdf2/dbsalt/le" has been observed on 4.1.12.55; sweep helpers below
#: cover raw-key and big-endian page numbers defensively.


@dataclass(frozen=True)
class DbHeader:
    db_path: Path
    salt: bytes          # 16 bytes from file header
    pages: tuple[bytes, ...]  # page1 is 4080 bytes (salt stripped), others 4096


def read_db_header(db_path: Path, pages: int = 2) -> DbHeader:
    resolved = Path(db_path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"database not found: {resolved}")
    with open(resolved, "rb") as fp:
        first = fp.read(PAGE_SIZE)
        if len(first) < PAGE_SIZE:
            raise ValueError(f"database too small for a page: {resolved}")
        salt = first[:16]
        page_list = [first[16:]]
        for _ in range(1, pages):
            chunk = fp.read(PAGE_SIZE)
            if len(chunk) != PAGE_SIZE:
                break
            page_list.append(chunk)
    return DbHeader(db_path=resolved, salt=salt, pages=tuple(page_list))


def derive_enc_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, salt, KDF_ITER, dklen=32)


def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, HMAC_ITER, dklen=32)


def verify_hmac(password: bytes, header: DbHeader, little_endian: bool = True) -> bool:
    """Check the first N pages' HMACs. Password is the *master key* (KDF applied here)."""
    enc_key = derive_enc_key(password, header.salt)
    mac_key = derive_mac_key(enc_key, header.salt)
    for index, page in enumerate(header.pages, start=1):
        if len(page) <= RESERVE:
            return False
        body = page[:-HMAC_SIZE]
        actual = page[-HMAC_SIZE:]
        calc = hmac.new(mac_key, body, hashlib.sha512)
        calc.update(index.to_bytes(4, "little" if little_endian else "big"))
        if not hmac.compare_digest(calc.digest(), actual):
            return False
    return True


def verify_hmac_sweep(password: bytes, header: DbHeader) -> tuple[bool, str]:
    """Try LE/BE page numbering; return (ok, endian-description)."""
    for little, label in ((True, "le"), (False, "be")):
        if verify_hmac(password, header, little_endian=little):
            return True, label
    return False, ""


def test_key_against_db(password_hex_or_bytes: str | bytes, db_path: Path) -> tuple[bool, str]:
    """Public 'test connection': does this key open this database?"""
    if isinstance(password_hex_or_bytes, str):
        try:
            password = bytes.fromhex(password_hex_or_bytes.strip())
        except ValueError as exc:
            return False, f"invalid hex: {exc}"
    else:
        password = password_hex_or_bytes
    if len(password) != 32:
        return False, f"password must be 32 bytes, got {len(password)}"
    try:
        header = read_db_header(db_path)
    except (OSError, ValueError) as exc:
        return False, f"cannot read db: {exc}"
    ok, endian = verify_hmac_sweep(password, header)
    if ok:
        return True, f"HMAC ok (variant pbkdf2-sha512-{KDF_ITER}/dbsalt/{endian})"
    return False, "HMAC mismatch: key does not open this database (or DB is not SQLCipher4)"
