from dataclasses import dataclass


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    nullable: bool = True
    default: str | None = None
    primary_key: bool = False
    autoincrement: bool = False
