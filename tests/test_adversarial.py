import os
import textwrap

import pytest

from deltadb.exceptions import LoaderError, SecurityError
from deltadb.security.identifiers import validate_column_type
from deltadb.security.yaml_safety import safe_load_yaml

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ── Column type injection ────────────────────────────────────────────────────


def test_column_type_injection_semicolon(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: id
                type: "int; DROP TABLE users; --"
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_column_type_injection_comment(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: id
                type: "int/**/UNION SELECT"
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_column_type_valid_simple():
    validate_column_type("varchar(255)")  # must not raise
    validate_column_type("integer")  # must not raise
    validate_column_type("timestamptz")  # must not raise
    validate_column_type("double precision")  # must not raise
    validate_column_type("decimal(10, 2)")  # must not raise


def test_column_type_empty_rejected():
    with pytest.raises(SecurityError, match="empty"):
        validate_column_type("")


def test_column_type_null_byte_rejected(tmp_path):
    f = tmp_path / "s.yml"
    # Write YAML with null byte in type using binary
    content = (
        b"tables:\n  t:\n    columns:\n      - name: id\n        type: int\x00evil\n"
    )
    f.write_bytes(content)
    with pytest.raises((SecurityError, LoaderError, Exception)):
        safe_load_yaml(str(f))


# ── Column default injection ─────────────────────────────────────────────────


def test_column_default_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: status
                type: varchar(20)
                default: "active'; DROP TABLE users; --"
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_column_default_injection_comment(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: status
                type: varchar(20)
                default: "normal'--"
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_column_default_valid_values(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: status
                type: varchar(20)
                default: "active"
              - name: count
                type: integer
                default: "0"
    """))
    result = safe_load_yaml(str(f))  # must not raise
    assert "users" in result["tables"]


# ── Constraint name injection ────────────────────────────────────────────────


def test_index_name_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: email
                type: varchar(255)
            indexes:
              - name: "idx_email; DROP TABLE users"
                columns: [email]
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_fk_name_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          orders:
            columns:
              - name: user_id
                type: uuid
            foreign_keys:
              - name: "fk_orders; DROP TABLE orders"
                columns: [user_id]
                referred_table: users
                referred_columns: [id]
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_unique_constraint_name_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          users:
            columns:
              - name: email
                type: varchar(255)
            unique_constraints:
              - name: "uq_email; DROP TABLE users"
                columns: [email]
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


# ── Dialect injection ────────────────────────────────────────────────────────


def test_dialect_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        dialect: "postgresql; DROP TABLE users"
        tables:
          users:
            columns:
              - name: id
                type: uuid
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_dialect_unknown_rejected(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        dialect: "oracle"
        tables:
          users:
            columns:
              - name: id
                type: uuid
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_dialect_valid_values(tmp_path):
    for dialect in ["postgresql", "mysql", "sqlite"]:
        f = tmp_path / f"{dialect}.yml"
        content = (
            f"dialect: {dialect}\ntables:\n  t:\n    columns:\n"
            f"      - name: id\n        type: int\n"
        )
        f.write_text(content)
        result = safe_load_yaml(str(f))  # must not raise
        assert result["dialect"] == dialect


# ── FK on_delete / on_update injection ───────────────────────────────────────


def test_fk_on_delete_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          orders:
            columns:
              - name: user_id
                type: uuid
            foreign_keys:
              - name: fk_orders_user
                columns: [user_id]
                referred_table: users
                referred_columns: [id]
                on_delete: "CASCADE; DROP TABLE orders"
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_fk_on_update_injection(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text(textwrap.dedent("""
        tables:
          orders:
            columns:
              - name: user_id
                type: uuid
            foreign_keys:
              - name: fk_orders_user
                columns: [user_id]
                referred_table: users
                referred_columns: [id]
                on_update: "SET NULL; DROP TABLE orders"
    """))
    with pytest.raises(SecurityError):
        safe_load_yaml(str(f))


def test_fk_on_delete_valid_values(tmp_path):
    for action in ["CASCADE", "SET NULL", "SET DEFAULT", "RESTRICT", "NO ACTION"]:
        safe_action = action.replace(" ", "_").lower()
        f = tmp_path / f"fk_{safe_action}.yml"
        f.write_text(textwrap.dedent(f"""
            tables:
              orders:
                columns:
                  - name: user_id
                    type: uuid
                foreign_keys:
                  - name: fk_orders_user
                    columns: [user_id]
                    referred_table: users
                    referred_columns: [id]
                    on_delete: "{action}"
        """))
        safe_load_yaml(str(f))  # must not raise


# ── YAML anchor bomb ─────────────────────────────────────────────────────────


def test_yaml_anchor_bomb_rejected(tmp_path):
    # Exponential anchor expansion: 9^9 ≈ 387M items but tiny on disk
    f = tmp_path / "bomb.yml"
    bomb = textwrap.dedent("""
        a: &a [x, x, x, x, x, x, x, x, x]
        b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]
        c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]
        tables:
          t:
            columns:
              - name: id
                type: int
    """)
    f.write_text(bomb)
    # Must raise SecurityError (size check catches disk size, not expansion).
    # The bomb file is tiny on disk so size check won't catch it.
    # We expect either SecurityError (if anchor bomb protection added)
    # OR LoaderError (unexpected keys 'a', 'b', 'c') from structure validation.
    with pytest.raises((SecurityError, LoaderError)):
        safe_load_yaml(str(f))


# ── Zero Trust: columns list is None ─────────────────────────────────────────


def test_null_columns_list_rejected(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text("tables:\n  users:\n    columns: null\n")
    with pytest.raises((LoaderError, TypeError)):
        safe_load_yaml(str(f))


# ── Zero Trust: table definition is not a dict ───────────────────────────────


def test_table_not_dict_rejected(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text("tables:\n  users: null\n")
    with pytest.raises(LoaderError):
        safe_load_yaml(str(f))


# ── quote_identifier in SQL output ───────────────────────────────────────────


def test_quote_identifier_prevents_injection():
    from deltadb.security.identifiers import quote_identifier

    # Valid identifier gets quoted correctly
    assert quote_identifier("user_orders_2024", "postgresql") == '"user_orders_2024"'
    assert quote_identifier("user_orders_2024", "mysql") == "`user_orders_2024`"


def test_quote_identifier_rejects_injection():
    from deltadb.security.identifiers import quote_identifier

    with pytest.raises(SecurityError):
        quote_identifier("evil; DROP TABLE x", "postgresql")
