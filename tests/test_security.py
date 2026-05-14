import os

import pytest
import yaml

from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import LoaderError, SecurityError
from deltadb.generator.dialects import Dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.model.column import Column
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.security.credentials import get_credential, mask_url
from deltadb.security.identifiers import quote_identifier, validate_identifier
from deltadb.security.path_safety import validate_output_path
from deltadb.security.yaml_safety import safe_load_yaml

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_mask_url_basic():
    url = "postgresql://admin:S3cr3t@host:5432/db"
    assert mask_url(url) == "postgresql://admin:****@host:5432/db"


def test_mask_url_special_chars_in_password():
    url = "mysql://root:p@ssword@host/db"
    assert mask_url(url) == "mysql://root:****@host/db"


def test_mask_url_no_password():
    url = "postgresql://host:5432/db"
    assert mask_url(url) == "postgresql://host:5432/db"


def test_get_credential_from_env_var(monkeypatch):
    monkeypatch.setenv("MY_SECRET", "myvalue")
    assert get_credential("MY_SECRET") == "myvalue"


def test_get_credential_prefers_secret_file(tmp_path, monkeypatch):
    secret_file = tmp_path / "pw.txt"
    secret_file.write_text("from_file\n")
    monkeypatch.setenv("MY_SECRET", "from_env")
    monkeypatch.setenv("MY_SECRET_FILE", str(secret_file))
    assert get_credential("MY_SECRET", "MY_SECRET_FILE") == "from_file"


def test_get_credential_returns_none_if_missing(monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    assert get_credential("MISSING_VAR") is None


def test_valid_identifier_passes():
    validate_identifier("users_2024")


def test_rejects_empty_identifier():
    with pytest.raises(SecurityError, match="cannot be empty"):
        validate_identifier("")


def test_rejects_sql_injection():
    with pytest.raises(SecurityError):
        validate_identifier("users; DROP TABLE orders; --")


def test_rejects_newline():
    with pytest.raises(SecurityError):
        validate_identifier("col\nDROP TABLE x")


def test_rejects_starts_with_digit():
    with pytest.raises(SecurityError):
        validate_identifier("1_invalid")


def test_rejects_too_long():
    with pytest.raises(SecurityError, match="too long"):
        validate_identifier("a" * 200)


def test_rejects_null_byte():
    with pytest.raises(SecurityError):
        validate_identifier("\x00col")


def test_quote_postgresql():
    assert quote_identifier("users", "postgresql") == '"users"'


def test_quote_mysql():
    assert quote_identifier("users", "mysql") == "`users`"


def test_quote_sqlite():
    assert quote_identifier("users", "sqlite") == '"users"'


def test_rejects_path_traversal():
    with pytest.raises(SecurityError, match="Path traversal"):
        validate_output_path("../../etc/cron.d/evil.sql")


def test_rejects_disallowed_extension():
    with pytest.raises(SecurityError, match="Unsupported output extension"):
        validate_output_path("output.sh")


def test_accepts_sql_extension(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = validate_output_path("migration.sql")
    assert p.suffix == ".sql"


def test_malicious_yaml_rejected():
    fixture = os.path.join(FIXTURES, "malicious_schema.yml")
    with pytest.raises(yaml.constructor.ConstructorError):
        safe_load_yaml(fixture)


def test_oversized_yaml_rejected(tmp_path):
    f = tmp_path / "big.yml"
    f.write_bytes(b"x" * (11 * 1024 * 1024))
    with pytest.raises(SecurityError, match="exceeds maximum size"):
        safe_load_yaml(str(f))


def test_unknown_root_key_rejected(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text(
        "tables:\n  t:\n    columns:\n      - name: id\n"
        "        type: int\nexploit: rm\n"
    )
    with pytest.raises(LoaderError, match="Unexpected keys"):
        safe_load_yaml(str(f))


# --- Additional adversarial tests ---


def test_rejects_single_quote_in_identifier():
    with pytest.raises(SecurityError):
        validate_identifier("col'--")


def test_rejects_comment_markers_in_identifier():
    with pytest.raises(SecurityError):
        validate_identifier("col/*injection*/")


def test_valid_table_2024_passes():
    validate_identifier("valid_table_2024")


def test_sql_generator_create_table_quoted(tmp_path):
    col = Column(name="id", type="integer", nullable=False, primary_key=True)
    tbl = Table(name="user_orders_2024", columns=(col,))
    schema = SchemaModel(tables={"user_orders_2024": tbl}, dialect="postgresql")
    change = Change(
        type=ChangeType.TABLE_ADDED,
        table="user_orders_2024",
        new_value=tbl,
    )
    gen = SqlGenerator(Dialect.POSTGRESQL)
    sql = gen.generate([change], schema)
    assert '"user_orders_2024"' in sql


def test_sql_generator_rejects_injection_in_table_name(tmp_path):
    col = Column(name="id", type="integer", nullable=False, primary_key=True)
    tbl = Table(name="user_orders_2024", columns=(col,))
    schema = SchemaModel(tables={"user_orders_2024": tbl}, dialect="postgresql")
    change = Change(
        type=ChangeType.TABLE_ADDED,
        table="evil; DROP TABLE x",
        new_value=tbl,
    )
    gen = SqlGenerator(Dialect.POSTGRESQL)
    with pytest.raises(SecurityError):
        gen.generate([change], schema)


def test_yaml_column_missing_type_raises_loader_error(tmp_path):
    f = tmp_path / "missing_type.yml"
    f.write_text("tables:\n  t:\n    columns:\n      - name: id\n")
    with pytest.raises(LoaderError, match="must have 'name' and 'type'"):
        safe_load_yaml(str(f))


def test_mask_url_password_with_at_and_hash():
    url = "mysql://root:p@ss#w0rd@host/db"
    masked = mask_url(url)
    assert "p@ss#w0rd" not in masked
    assert "****" in masked
    assert masked.startswith("mysql://root:****@")


def test_db_loader_operational_error_no_password():
    from unittest.mock import MagicMock, patch

    from sqlalchemy.exc import OperationalError

    from deltadb.exceptions import LoaderError
    from deltadb.loader.db_loader import DbLoader

    url = "postgresql://admin:SuperSecret99@host:5432/db"
    loader = DbLoader(url)

    fake_engine = MagicMock()
    fake_engine.dialect.name = "postgresql"
    fake_engine.dispose = MagicMock()

    op_err = OperationalError("connection refused", None, None)

    with patch("deltadb.loader.db_loader.create_engine", return_value=fake_engine):
        with patch("deltadb.loader.db_loader.inspect", side_effect=op_err):
            with pytest.raises(LoaderError) as exc_info:
                loader.load()

    assert "SuperSecret99" not in str(exc_info.value)
