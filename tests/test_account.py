from pathlib import Path

from chattrace.keyagent.account import discover_accounts, is_account_dir, resolve_account


def _make_account(root: Path, name: str) -> Path:
    acc = root / name
    (acc / "db_storage" / "message").mkdir(parents=True)
    (acc / "db_storage" / "message" / "message_0.db").write_bytes(b"x" * 100)
    return acc


def test_is_account_dir(tmp_path: Path):
    acc = _make_account(tmp_path, "wxid_a_0001")
    assert is_account_dir(acc)
    assert not is_account_dir(tmp_path)


def test_discover_and_resolve(tmp_path: Path):
    _make_account(tmp_path, "wxid_a_0001")
    _make_account(tmp_path, "wxid_b_0002")
    accounts = discover_accounts(tmp_path)
    assert {a.account_id for a in accounts} == {"wxid_a_0001", "wxid_b_0002"}
    chosen = resolve_account(tmp_path)
    assert chosen.account_id in {"wxid_a_0001", "wxid_b_0002"}
    direct = resolve_account(tmp_path / chosen.account_id)
    assert direct.account_id == chosen.account_id
