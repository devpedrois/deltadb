from deltadb.loader.base import BaseLoader
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, PrimaryKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.model.types import normalize_type
from deltadb.security.yaml_safety import safe_load_yaml


class YamlLoader(BaseLoader):
    def __init__(self, file_path: str) -> None:
        self._file_path = file_path

    def load(self) -> SchemaModel:
        data = safe_load_yaml(self._file_path)
        dialect = data.get("dialect")
        tables: dict[str, Table] = {}
        for table_name, table_def in data["tables"].items():
            tables[table_name] = _parse_table(
                table_name, table_def, dialect or "postgresql"
            )
        return SchemaModel(tables=tables, dialect=dialect)


def _parse_table(name: str, table_def: dict, dialect: str) -> Table:
    columns = tuple(
        Column(
            name=col["name"],
            type=normalize_type(col["type"], dialect),
            nullable=col.get("nullable", True),
            default=str(col["default"]) if col.get("default") is not None else None,
            primary_key=col.get("primary_key", False),
            autoincrement=col.get("autoincrement", False),
        )
        for col in table_def["columns"]
    )
    pk_cols = tuple(c.name for c in columns if c.primary_key)
    primary_key = PrimaryKey(name=None, columns=pk_cols) if pk_cols else None

    indexes = tuple(
        Index(
            name=idx["name"],
            columns=tuple(idx["columns"]),
            unique=idx.get("unique", False),
        )
        for idx in table_def.get("indexes", [])
    )
    foreign_keys = tuple(
        ForeignKey(
            name=fk.get("name"),
            columns=tuple(fk["columns"]),
            referred_table=fk["referred_table"],
            referred_columns=tuple(fk["referred_columns"]),
            on_delete=fk.get("on_delete"),
            on_update=fk.get("on_update"),
        )
        for fk in table_def.get("foreign_keys", [])
    )
    unique_constraints = tuple(
        UniqueConstraint(
            name=uc.get("name"),
            columns=tuple(uc["columns"]),
        )
        for uc in table_def.get("unique_constraints", [])
    )
    return Table(
        name=name,
        columns=columns,
        primary_key=primary_key,
        foreign_keys=foreign_keys,
        indexes=indexes,
        unique_constraints=unique_constraints,
    )
