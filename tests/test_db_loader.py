import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from sqlalchemy import (
    Column as SAColumn,
)
from sqlalchemy import (
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
)

from deltadb.cli import deltadb
from deltadb.exceptions import LoaderError, SecurityError
from deltadb.loader.db_loader import DbLoader


def _create_sqlite_db() -> tuple[str, str]:
    """Return (url, tmp_path) for a file-based SQLite DB with users + orders."""
    tmp = tempfile.mktemp(suffix=".db")
    url = f"sqlite:///{tmp}"
    engine = create_engine(url)
    meta = MetaData()
    users = Table(
        "users",
        meta,
        SAColumn("id", Integer, primary_key=True, autoincrement=True),
        SAColumn("email", String(255), nullable=False, unique=True),
        SAColumn("name", String(100), nullable=True),
    )
    Index("idx_users_email", users.c.email, unique=True)
    Table(
        "orders",
        meta,
        SAColumn("id", Integer, primary_key=True, autoincrement=True),
        SAColumn("user_id", Integer, ForeignKey("users.id"), nullable=False),
        SAColumn("amount", Integer, nullable=True),
    )
    meta.create_all(engine)
    engine.dispose()
    return url, tmp


def test_sqlite_reflection_tables():
    url, tmp = _create_sqlite_db()
    try:
        schema = DbLoader(url).load()
        assert "users" in schema.tables
        assert "orders" in schema.tables
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_sqlite_reflection_columns():
    url, tmp = _create_sqlite_db()
    try:
        schema = DbLoader(url).load()
        col_names = {c.name for c in schema.tables["users"].columns}
        assert {"id", "email", "name"} == col_names
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_sqlite_foreign_key():
    url, tmp = _create_sqlite_db()
    try:
        schema = DbLoader(url).load()
        fks = schema.tables["orders"].foreign_keys
        assert len(fks) == 1
        assert fks[0].referred_table == "users"
        assert "user_id" in fks[0].columns
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_sqlite_index():
    url, tmp = _create_sqlite_db()
    try:
        schema = DbLoader(url).load()
        indexes = schema.tables["users"].indexes
        idx_names = [idx.name for idx in indexes]
        assert any("email" in n for n in idx_names)
        email_idx = next(idx for idx in indexes if "email" in idx.name)
        assert email_idx.unique is True
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_scheme_ftp_rejected():
    with pytest.raises(SecurityError, match="Unsupported database scheme"):
        DbLoader("ftp://malicious.com/db")


def test_scheme_file_rejected():
    with pytest.raises(SecurityError, match="Unsupported database scheme"):
        DbLoader("file:///etc/passwd")


def test_error_masks_credentials():
    loader = DbLoader("postgresql://admin:S3cr3t@127.0.0.1:1/nonexistent")
    with pytest.raises(LoaderError) as exc_info:
        loader.load()
    # [SECURITY] Raw password must never appear in the error message
    assert "S3cr3t" not in str(exc_info.value)
    assert "****" in str(exc_info.value)


@pytest.mark.integration
def test_postgresql_reflection(pg_url):
    from sqlalchemy import text

    engine = create_engine(pg_url)
    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS pg_test_users "
                "(id SERIAL PRIMARY KEY, username VARCHAR(100) NOT NULL)"
            )
        )
        conn.commit()
    engine.dispose()

    loader = DbLoader(pg_url)
    schema = loader.load()
    assert "pg_test_users" in schema.tables
    table = schema.tables["pg_test_users"]
    col_names = {c.name for c in table.columns}
    assert "id" in col_names
    assert "username" in col_names
    assert schema.dialect == "postgresql"


@pytest.mark.integration
def test_mysql_reflection(mysql_url):
    from sqlalchemy import text

    engine = create_engine(mysql_url)
    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS mysql_test_items "
                "(id INT AUTO_INCREMENT PRIMARY KEY, label VARCHAR(100) NOT NULL)"
            )
        )
        conn.commit()
    engine.dispose()

    loader = DbLoader(mysql_url)
    schema = loader.load()
    assert "mysql_test_items" in schema.tables
    assert schema.dialect == "mysql"


@pytest.mark.integration
def test_valid_identifier_table_name(pg_url):
    from sqlalchemy import text

    engine = create_engine(pg_url)
    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS user_accounts_2024 "
                "(id SERIAL PRIMARY KEY, created_at TIMESTAMP)"
            )
        )
        conn.commit()
    engine.dispose()

    loader = DbLoader(pg_url)
    schema = loader.load()
    assert "user_accounts_2024" in schema.tables


def test_snapshot_cli_e2e():
    url, tmp = _create_sqlite_db()
    try:
        runner = CliRunner()
        result = runner.invoke(deltadb, ["snapshot", url])
        assert result.exit_code == 0
        assert "users" in result.output
        assert "orders" in result.output
    finally:
        Path(tmp).unlink(missing_ok=True)
