import os

import pytest
import yaml

from deltadb.exceptions import LoaderError, SecurityError
from deltadb.loader.yaml_loader import YamlLoader

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_loads_schema_a_tables():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_a.yml"))
    schema = loader.load()
    assert set(schema.tables.keys()) == {"users", "orders"}


def test_loads_schema_a_dialect():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_a.yml"))
    schema = loader.load()
    assert schema.dialect == "postgresql"


def test_loads_users_columns():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_a.yml"))
    schema = loader.load()
    col_names = [c.name for c in schema.tables["users"].columns]
    assert "id" in col_names
    assert "email" in col_names
    assert "created_at" in col_names


def test_loads_orders_foreign_key():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_a.yml"))
    schema = loader.load()
    fks = schema.tables["orders"].foreign_keys
    assert len(fks) == 1
    assert fks[0].referred_table == "users"
    assert fks[0].on_delete == "CASCADE"


def test_loads_users_index():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_a.yml"))
    schema = loader.load()
    idxs = schema.tables["users"].indexes
    assert len(idxs) == 1
    assert idxs[0].name == "idx_users_email"
    assert idxs[0].unique is True


def test_loads_users_unique_constraint():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_a.yml"))
    schema = loader.load()
    ucs = schema.tables["users"].unique_constraints
    assert len(ucs) == 1
    assert ucs[0].name == "uq_users_email"


def test_rejects_unknown_root_key(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text(
        "tables:\n  t:\n    columns:\n      - name: id\n"
        "        type: int\nexploit: rm -rf\n"
    )
    loader = YamlLoader(str(f))
    with pytest.raises(LoaderError, match="Unexpected keys"):
        loader.load()


def test_rejects_missing_tables(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text("dialect: postgresql\n")
    loader = YamlLoader(str(f))
    with pytest.raises(LoaderError, match="'tables'"):
        loader.load()


def test_rejects_malicious_yaml():
    fixture = os.path.join(FIXTURES, "malicious_schema.yml")
    loader = YamlLoader(fixture)
    with pytest.raises(yaml.constructor.ConstructorError):
        loader.load()


def test_rejects_oversized_yaml(tmp_path):
    f = tmp_path / "big.yml"
    f.write_bytes(b"x" * (11 * 1024 * 1024))
    loader = YamlLoader(str(f))
    with pytest.raises(SecurityError, match="exceeds maximum size"):
        loader.load()


def test_rejects_column_without_type(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text("tables:\n  users:\n    columns:\n      - name: id\n")
    loader = YamlLoader(str(f))
    with pytest.raises(LoaderError, match="'name' and 'type'"):
        loader.load()


def test_schema_b_has_phone_column():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_b.yml"))
    schema = loader.load()
    col_names = [c.name for c in schema.tables["users"].columns]
    assert "phone" in col_names


def test_schema_b_has_products_table():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_b.yml"))
    schema = loader.load()
    assert "products" in schema.tables


def test_schema_b_orders_no_foreign_key():
    loader = YamlLoader(os.path.join(FIXTURES, "schema_b.yml"))
    schema = loader.load()
    assert schema.tables["orders"].foreign_keys == ()


def test_rejects_numeric_index_column_name(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text(
        "tables:\n  t:\n    columns:\n      - name: id\n        type: int\n"
        "    indexes:\n      - name: idx_t\n        columns: [123]\n"
    )
    with pytest.raises(LoaderError, match="Expected a string"):
        YamlLoader(str(f)).load()


def test_rejects_numeric_fk_column_name(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text(
        "tables:\n  t:\n    columns:\n      - name: id\n        type: int\n"
        "    foreign_keys:\n      - columns: [123]\n        referred_table: other\n"
        "        referred_columns: [id]\n"
    )
    with pytest.raises(LoaderError, match="Expected a string"):
        YamlLoader(str(f)).load()


def test_rejects_numeric_uc_column_name(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text(
        "tables:\n  t:\n    columns:\n      - name: id\n        type: int\n"
        "    unique_constraints:\n      - columns: [42]\n"
    )
    with pytest.raises(LoaderError, match="Expected a string"):
        YamlLoader(str(f)).load()
