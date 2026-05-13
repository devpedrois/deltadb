from dataclasses import dataclass


@dataclass(frozen=True)
class PrimaryKey:
    name: str | None
    columns: tuple[str, ...]


@dataclass(frozen=True)
class ForeignKey:
    name: str | None
    columns: tuple[str, ...]
    referred_table: str
    referred_columns: tuple[str, ...]
    on_delete: str | None = None
    on_update: str | None = None


@dataclass(frozen=True)
class UniqueConstraint:
    name: str | None
    columns: tuple[str, ...]
