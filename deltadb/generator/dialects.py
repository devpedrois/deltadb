from enum import Enum

from deltadb.config import SUPPORTED_DIALECTS
from deltadb.exceptions import DeltaDbError


class Dialect(Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"


def detect_dialect(url: str | None, schema_dialect: str | None) -> Dialect:
    candidate = None

    if url:
        lower = url.lower()
        if lower.startswith("postgresql") or lower.startswith("postgres"):
            candidate = "postgresql"
        elif lower.startswith("mysql"):
            candidate = "mysql"
        elif lower.startswith("sqlite"):
            candidate = "sqlite"

    if candidate is None and schema_dialect:
        candidate = schema_dialect.lower()

    if candidate is None:
        return Dialect.POSTGRESQL

    if candidate not in SUPPORTED_DIALECTS:
        raise DeltaDbError(
            f"Unknown dialect '{candidate}'. Allowed: {SUPPORTED_DIALECTS}"
        )

    return Dialect(candidate)
