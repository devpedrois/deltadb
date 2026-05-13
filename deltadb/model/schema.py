from dataclasses import dataclass

from deltadb.model.table import Table


@dataclass(frozen=True)
class SchemaModel:
    tables: dict[str, Table]
    dialect: str | None = None
