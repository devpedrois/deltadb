import os

import pytest
import yaml

from deltadb.exceptions import LoaderError, SecurityError
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
