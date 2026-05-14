_TYPE_ALIASES: dict[str, str] = {
    "int": "integer",
    "int2": "smallint",
    "int4": "integer",
    "int8": "bigint",
    "bool": "boolean",
    "float4": "real",
    "float8": "double precision",
    "character varying": "varchar",
}

_MYSQL_EXTRA_ALIASES: dict[str, str] = {
    "tinyint(1)": "boolean",
    "int unsigned": "integer",
    "bigint unsigned": "bigint",
}

_PG_EXTRA_ALIASES: dict[str, str] = {
    "serial": "integer",
    "bigserial": "bigint",
    "smallserial": "smallint",
}

_DIALECT_ALIASES: dict[str, dict[str, str]] = {
    "mysql": _MYSQL_EXTRA_ALIASES,
    "postgresql": _PG_EXTRA_ALIASES,
}


def normalize_type(raw_type: str, dialect: str) -> str:
    normalized = raw_type.strip().lower()
    base = normalized.split("(")[0].strip()

    # Dialect-specific aliases take priority — handle equivalences invisible to the shared table
    dialect_aliases = _DIALECT_ALIASES.get(dialect, {})
    if normalized in dialect_aliases:
        return dialect_aliases[normalized]
    if base in dialect_aliases:
        return dialect_aliases[base] + normalized[len(base):]

    # Shared cross-dialect aliases
    if base in _TYPE_ALIASES:
        return _TYPE_ALIASES[base] + normalized[len(base):]
    return normalized
