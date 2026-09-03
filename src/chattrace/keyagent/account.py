"""Account directory discovery (mirrors chatlog-studio semantics, Windows xwechat_files)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ACCOUNT_DB_REL = Path("db_storage") / "message" / "message_0.db"


@dataclass(frozen=True)
class Account:
    account_id: str  # directory name, e.g. wxid_xxx_8146
    account_dir: Path
    message_db: Path


def is_account_dir(path: Path) -> bool:
    return (Path(path) / ACCOUNT_DB_REL).exists()


def discover_accounts(root: Path) -> list[Account]:
    """List account directories directly under an xwechat_files root."""
    out: list[Account] = []
    root = Path(root)
    if not root.exists():
        return out
    for child in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if child.is_dir():
            db = child / ACCOUNT_DB_REL
            if db.exists():
                out.append(Account(account_id=child.name, account_dir=child, message_db=db))
    return out


def resolve_account(source: Path) -> Account:
    """Accept either an account directory or an xwechat_files root containing one."""
    source = Path(source)
    if is_account_dir(source):
        return Account(account_id=source.name, account_dir=source, message_db=source / ACCOUNT_DB_REL)
    accounts = discover_accounts(source)
    if not accounts:
        raise FileNotFoundError(
            f"no WeChat account directory found under {source} "
            f"(expected {ACCOUNT_DB_REL})"
        )
    return accounts[0]
