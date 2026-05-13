import pytest

from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, PrimaryKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.model.types import normalize_type


def test_column_is_frozen():
    col = Column(name="id", type="uuid", nullable=False, primary_key=True)
    with pytest.raises((TypeError, AttributeError)):
        col.name = "other"  # type: ignore[misc]


def test_column_defaults():
    col = Column(name="email", type="varchar(255)")
    assert col.nullable is True
    assert col.default is None
    assert col.primary_key is False
    assert col.autoincrement is False


def test_index_is_frozen():
    idx = Index(name="idx_email", columns=("email",), unique=True)
    with pytest.raises((TypeError, AttributeError)):
        idx.name = "other"  # type: ignore[misc]


def test_foreign_key_fields():
    fk = ForeignKey(
        name="fk_orders_user",
        columns=("user_id",),
        referred_table="users",
        referred_columns=("id",),
        on_delete="CASCADE",
    )
    assert fk.referred_table == "users"
    assert fk.on_delete == "CASCADE"
    assert fk.on_update is None


def test_primary_key_fields():
    pk = PrimaryKey(name="pk_users", columns=("id",))
    assert pk.columns == ("id",)


def test_unique_constraint_fields():
    uc = UniqueConstraint(name="uq_email", columns=("email",))
    assert uc.columns == ("email",)


def test_table_is_frozen():
    col = Column(name="id", type="uuid", nullable=False, primary_key=True)
    t = Table(name="users", columns=(col,))
    with pytest.raises((TypeError, AttributeError)):
        t.name = "other"  # type: ignore[misc]


def test_table_defaults():
    col = Column(name="id", type="uuid")
    t = Table(name="users", columns=(col,))
    assert t.primary_key is None
    assert t.foreign_keys == ()
    assert t.indexes == ()
    assert t.unique_constraints == ()


def test_schema_model_access_by_name():
    col = Column(name="id", type="uuid", nullable=False, primary_key=True)
    t = Table(name="users", columns=(col,))
    schema = SchemaModel(tables={"users": t})
    assert schema.tables["users"].name == "users"


def test_normalize_type_lowercase():
    assert normalize_type("UUID", "postgresql") == "uuid"
    assert normalize_type("  TEXT  ", "postgresql") == "text"


def test_normalize_type_int_alias():
    assert normalize_type("INT", "postgresql") == "integer"


def test_normalize_type_varchar_passthrough():
    assert normalize_type("VARCHAR(255)", "postgresql") == "varchar(255)"


def test_normalize_type_bool_alias():
    assert normalize_type("BOOL", "postgresql") == "boolean"
