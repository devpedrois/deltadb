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


def normalize_type(raw_type: str, dialect: str) -> str:
    normalized = raw_type.strip().lower()
    base = normalized.split("(")[0].strip()
    if base in _TYPE_ALIASES:
        return _TYPE_ALIASES[base] + normalized[len(base) :]
    return normalized
