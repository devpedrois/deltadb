from dataclasses import dataclass

from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, PrimaryKey, UniqueConstraint
from deltadb.model.index import Index


@dataclass(frozen=True)
class Table:
    name: str
    columns: tuple[Column, ...]
    primary_key: PrimaryKey | None = None
    foreign_keys: tuple[ForeignKey, ...] = ()
    indexes: tuple[Index, ...] = ()
    unique_constraints: tuple[UniqueConstraint, ...] = ()
