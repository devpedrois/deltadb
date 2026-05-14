import logging
from pathlib import Path

import yaml

from deltadb.config import (
    MAX_COLUMNS_PER_TABLE,
    MAX_TABLES,
    MAX_YAML_SIZE_BYTES,
    SUPPORTED_DIALECTS,
)
from deltadb.exceptions import LoaderError, SecurityError
from deltadb.security.identifiers import (
    validate_column_type,
    validate_default,
    validate_identifier,
)

logger = logging.getLogger(__name__)

_ALLOWED_ROOT_KEYS = {"dialect", "tables"}


class _NoDuplicateKeyLoader(yaml.SafeLoader):
    """SafeLoader subclass that raises LoaderError on duplicate YAML keys.

    PyYAML's safe_load silently overwrites duplicate keys with the last value.
    Duplicate table or column names would silently lose schema definitions.
    """

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        keys = [self.construct_object(k, deep=deep) for k, _ in node.value]
        duplicates = [k for k in keys if keys.count(k) > 1]
        if duplicates:
            raise LoaderError(f"Duplicate keys in YAML: {sorted(set(str(d) for d in duplicates))}")
        return super().construct_mapping(node, deep=deep)
_ALLOWED_TABLE_KEYS = {"columns", "indexes", "foreign_keys", "unique_constraints"}

# [SECURITY] Allowlist for FK referential actions — prevents action-field injection
_ALLOWED_FK_ACTIONS = frozenset(
    {"CASCADE", "SET NULL", "SET DEFAULT", "RESTRICT", "NO ACTION"}
)


def safe_load_yaml(file_path: str) -> dict:
    path = Path(file_path)
    if not path.exists():
        raise LoaderError(f"File not found: {file_path}")
    # [SECURITY] File size check — prevents memory exhaustion from oversized YAML
    if path.stat().st_size > MAX_YAML_SIZE_BYTES:
        max_mb = MAX_YAML_SIZE_BYTES // 1024 // 1024
        raise SecurityError(f"YAML file exceeds maximum size of {max_mb}MB. Aborting.")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    # [SECURITY] _NoDuplicateKeyLoader extends SafeLoader — safe against code execution.
    # Duplicate key detection catches silently overwritten table/column definitions.
    data = yaml.load(content, Loader=_NoDuplicateKeyLoader)  # nosec B506
    if not isinstance(data, dict):
        raise LoaderError("YAML root must be a mapping")
    _validate_yaml_structure(data)
    return data


def _validate_dialect(dialect: str | None) -> None:
    # [SECURITY] Dialect allowlist — prevents dialect-field injection
    if dialect is not None and dialect not in SUPPORTED_DIALECTS:
        raise SecurityError(
            f"Unsupported dialect '{dialect}'. Allowed: {SUPPORTED_DIALECTS}"
        )


def _validate_fk_action(action: str | None, field: str) -> None:
    # [SECURITY] FK action allowlist — prevents on_delete/on_update injection
    if action is not None and action.upper() not in _ALLOWED_FK_ACTIONS:
        raise SecurityError(
            f"Invalid FK {field} '{action}'. Allowed: {_ALLOWED_FK_ACTIONS}"
        )


def _validate_yaml_structure(data: dict) -> None:
    # [SECURITY] Allowlist of expected keys — reject unexpected keys
    # to prevent injection via YAML
    unexpected = set(data.keys()) - _ALLOWED_ROOT_KEYS
    if unexpected:
        raise LoaderError(
            f"Unexpected keys in YAML: {unexpected}. Allowed: {_ALLOWED_ROOT_KEYS}"
        )
    # [SECURITY] Validate dialect against allowlist before storing in model
    _validate_dialect(data.get("dialect"))
    if "tables" not in data or not isinstance(data["tables"], dict):
        raise LoaderError("YAML must have 'tables' as a mapping")
    # [SECURITY] Anchor-expansion DoS — reject schemas with excessive table count
    if len(data["tables"]) > MAX_TABLES:
        raise SecurityError(
            f"Table count {len(data['tables'])} exceeds maximum {MAX_TABLES}. "
            "Possible anchor-expansion DoS."
        )
    for table_name, table_def in data["tables"].items():
        # [SECURITY] Validate table names as SQL identifiers — defense in depth
        validate_identifier(str(table_name))
        if not isinstance(table_def, dict):
            raise LoaderError(f"Table '{table_name}' must be a mapping")
        if "columns" not in table_def:
            raise LoaderError(f"Table '{table_name}' must have 'columns'")
        if not isinstance(table_def["columns"], list):
            raise LoaderError(f"Table '{table_name}' columns must be a list")
        unexpected_table = set(table_def.keys()) - _ALLOWED_TABLE_KEYS
        if unexpected_table:
            raise LoaderError(
                f"Unexpected keys in table '{table_name}': {unexpected_table}"
            )
        # [SECURITY] Anchor-expansion DoS — reject tables with excessive column count
        if len(table_def["columns"]) > MAX_COLUMNS_PER_TABLE:
            raise SecurityError(
                f"Column count {len(table_def['columns'])} in table '{table_name}' "
                f"exceeds maximum {MAX_COLUMNS_PER_TABLE}."
            )
        for col in table_def["columns"]:
            if not isinstance(col, dict) or "name" not in col or "type" not in col:
                raise LoaderError(
                    f"Each column in table '{table_name}' must have 'name' and 'type'"
                )
            # [SECURITY] Validate column names as SQL identifiers — defense in depth
            validate_identifier(str(col["name"]))
            # [SECURITY] Explicit None check — YAML 'type: null' sets col["type"]=None;
            # str(None)="None" passes the regex without this guard.
            if col["type"] is None:
                raise LoaderError(
                    f"Column type cannot be null in table '{table_name}'"
                )
            # [SECURITY] Validate column type — prevents type-field SQL injection
            validate_column_type(str(col["type"]))
            # [SECURITY] Validate default values — reject SQL metacharacters
            if col.get("default") is not None:
                validate_default(str(col["default"]))
        for idx in table_def.get("indexes", []):
            # [SECURITY] Validate index name — prevent identifier injection
            if idx.get("name") is not None:
                validate_identifier(str(idx["name"]))
            for col_name in idx.get("columns", []):
                validate_identifier(str(col_name))
        for fk in table_def.get("foreign_keys", []):
            # [SECURITY] Validate FK name, column names, referred table/columns, actions
            if fk.get("name") is not None:
                validate_identifier(str(fk["name"]))
            for col_name in fk.get("columns", []):
                validate_identifier(str(col_name))
            if "referred_table" in fk:
                validate_identifier(str(fk["referred_table"]))
            for col_name in fk.get("referred_columns", []):
                validate_identifier(str(col_name))
            _validate_fk_action(fk.get("on_delete"), "on_delete")
            _validate_fk_action(fk.get("on_update"), "on_update")
        for uc in table_def.get("unique_constraints", []):
            # [SECURITY] Validate unique constraint name and column names
            if uc.get("name") is not None:
                validate_identifier(str(uc["name"]))
            for col_name in uc.get("columns", []):
                validate_identifier(str(col_name))
