from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class SchemaModel:
    tables: MappingProxyType
    dialect: str | None = None

    def __post_init__(self) -> None:
        # [SECURITY] Wrap plain dict in MappingProxyType — frozen=True only prevents
        # attribute reassignment; the dict itself would still be mutable without this.
        if isinstance(self.tables, dict):
            object.__setattr__(self, "tables", MappingProxyType(self.tables))
