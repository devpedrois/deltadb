import logging
from urllib.parse import urlparse

from sqlalchemy import create_engine, inspect

from deltadb.config import CONNECTION_TIMEOUT, SUPPORTED_DIALECTS
from deltadb.exceptions import LoaderError, SecurityError
from deltadb.loader.base import BaseLoader
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, PrimaryKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.model.types import normalize_type
from deltadb.security.credentials import mask_url
from deltadb.security.identifiers import validate_identifier, validate_reflected_default

logger = logging.getLogger(__name__)

# [SECURITY] Characters that must never appear in reflected values (null byte,
# newline). Stricter allowlist is applied via validate_identifier for names.
_DANGEROUS_BYTES = ("\x00", "\n", "\r")


class DbLoader(BaseLoader):
    def __init__(self, connection_url: str) -> None:
        self._url = connection_url
        self._validate_url()
        # [SECURITY] Never log the raw URL — always mask password
        logger.info("Loader initialized for: %s", mask_url(connection_url))

    def _validate_url(self) -> None:
        # [SECURITY] Connection string scheme validation — allowlist only
        parsed = urlparse(self._url)
        scheme = parsed.scheme.split("+")[0]
        if scheme not in SUPPORTED_DIALECTS:
            raise SecurityError(
                f"Unsupported database scheme: '{scheme}'. "
                f"Allowed: {SUPPORTED_DIALECTS}. "
                "Other schemes are not supported for security reasons."
            )

    def load(self) -> SchemaModel:
        engine = None
        try:
            # [SECURITY] Scheme-based timeout — NOT substring search on full URL.
            # "postgresql://host/sqlite_db" has "sqlite" in it but needs a timeout.
            parsed = urlparse(self._url)
            scheme = parsed.scheme.split("+")[0]
            connect_args: dict = {}
            if scheme != "sqlite":
                connect_args["connect_timeout"] = CONNECTION_TIMEOUT

            engine = create_engine(
                self._url, connect_args=connect_args, pool_pre_ping=True
            )
            inspector = inspect(engine)
            dialect_name = engine.dialect.name
            tables: dict[str, Table] = {}
            for table_name in inspector.get_table_names():
                # [SECURITY] Zero Trust — table names from external DB are untrusted
                # input. Validate before storing in SchemaModel or generating SQL.
                validate_identifier(table_name)
                tables[table_name] = self._reflect_table(
                    inspector, table_name, dialect_name
                )
            return SchemaModel(tables=tables, dialect=dialect_name)
        except SecurityError:
            raise
        except Exception as e:
            # [SECURITY] Never expose raw error with connection string.
            # Use `from None` to break the cause chain — the original SQLAlchemy
            # exception may include the raw connection URL in its message.
            safe_url = mask_url(self._url)
            raise LoaderError(
                f"Failed to load schema from {safe_url}: {type(e).__name__}"
            ) from None
        finally:
            # [SECURITY] Always dispose engine — prevents resource leak when
            # SecurityError is raised mid-reflection.
            if engine is not None:
                engine.dispose()

    def _reflect_table(
        self, inspector, table_name: str, dialect: str
    ) -> Table:
        raw_cols = inspector.get_columns(table_name)
        pk_info = inspector.get_pk_constraint(table_name)
        pk_col_names = set(pk_info.get("constrained_columns", []))

        columns = []
        for c in raw_cols:
            # [SECURITY] Zero Trust — column names from external DB are untrusted
            validate_identifier(c["name"])
            col_default = None
            if c.get("default") is not None:
                raw_default = str(c["default"])
                # [SECURITY] Reject control characters in reflected defaults
                _reject_dangerous_bytes(raw_default, "column default")
                # [SECURITY] Reject SQL injection patterns in reflected defaults.
                # Uses validate_reflected_default (not validate_default) because
                # legitimate DB expressions like nextval('seq'::regclass) contain quotes.
                validate_reflected_default(raw_default)
                col_default = raw_default
            columns.append(Column(
                name=c["name"],
                type=normalize_type(str(c["type"]), dialect),
                nullable=c.get("nullable", True),
                default=col_default,
                primary_key=c["name"] in pk_col_names,
                autoincrement=bool(c.get("autoincrement", False)),
            ))

        pk = (
            PrimaryKey(
                name=pk_info.get("name"),
                columns=tuple(pk_info.get("constrained_columns", [])),
            )
            if pk_info.get("constrained_columns")
            else None
        )

        fks = []
        for fk in inspector.get_foreign_keys(table_name):
            # [SECURITY] Validate FK column names and referred table from DB
            for col_name in fk.get("constrained_columns", []):
                validate_identifier(col_name)
            validate_identifier(fk["referred_table"])
            for col_name in fk.get("referred_columns", []):
                validate_identifier(col_name)
            fks.append(ForeignKey(
                name=fk.get("name"),
                columns=tuple(fk["constrained_columns"]),
                referred_table=fk["referred_table"],
                referred_columns=tuple(fk["referred_columns"]),
                on_delete=fk.get("options", {}).get("ondelete"),
                on_update=fk.get("options", {}).get("onupdate"),
            ))

        indexes = []
        for idx in inspector.get_indexes(table_name):
            if not idx.get("name"):
                continue
            # [SECURITY] Validate index name and column names from DB
            validate_identifier(idx["name"])
            valid_cols: list[str] = []
            for col_name in idx.get("column_names", []):
                if col_name is None:
                    # Functional/expression indexes return None for the column name
                    logger.warning(
                        "Index '%s' on table '%s' has a functional/expression column — skipped",
                        idx["name"], table_name,
                    )
                    continue
                validate_identifier(col_name)
                valid_cols.append(col_name)
            indexes.append(Index(
                name=idx["name"],
                columns=tuple(valid_cols),
                unique=bool(idx.get("unique", False)),
            ))

        uqs = []
        for uq in (
            inspector.get_unique_constraints(table_name)
            if hasattr(inspector, "get_unique_constraints")
            else []
        ):
            if uq.get("name"):
                validate_identifier(uq["name"])
            for col_name in uq.get("column_names", []):
                validate_identifier(col_name)
            uqs.append(UniqueConstraint(
                name=uq.get("name"),
                columns=tuple(uq["column_names"]),
            ))

        return Table(
            name=table_name,
            columns=tuple(columns),
            primary_key=pk,
            foreign_keys=tuple(fks),
            indexes=tuple(indexes),
            unique_constraints=tuple(uqs),
        )


def _reject_dangerous_bytes(value: str, field: str) -> None:
    for char in _DANGEROUS_BYTES:
        if char in value:
            raise SecurityError(
                f"Dangerous control character in {field}: {repr(char)}"
            )
