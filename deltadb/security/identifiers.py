import re

from deltadb.config import MAX_IDENTIFIER_LENGTH, SUPPORTED_DIALECTS
from deltadb.exceptions import SecurityError

# [SECURITY] Allowlist approach — only explicitly allowed characters pass
VALID_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# [SECURITY] Blocklist for characters that cannot survive the regex above but
# are kept for defense-in-depth on raw strings before regex validation runs.
# NOTE: after VALID_IDENTIFIER_RE passes, only xp_ prefix is still meaningful.
_IDENTIFIER_CHAR_BLOCKLIST = [";", "--", "/*", "*/", "\n", "\r", "\x00", "\\"]

# [SECURITY] Allowlist for SQL column types. Supports:
#   - Simple:          integer, boolean, jsonb
#   - Parameterized:   varchar(255), numeric(10, 2)
#   - Multi-word:      double precision, character varying(255)
#   - Hyphenated:      user-defined  (SQLAlchemy reflects custom/enum types this way)
#   - Array suffix:    integer[], varchar(255)[]  (PostgreSQL ARRAY columns)
# The (?:\[\])* at the end matches zero or more [] suffixes for array dimensions.
VALID_TYPE_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9 _-]*(?: *\([a-zA-Z0-9, ]+\))?(?:\[\])*$"
)
_TYPE_DANGEROUS = [";", "--", "/*", "*/", "\n", "\r", "\x00"]

# [SECURITY] SQL DDL/DML keywords blocked in column type fields.
# Spaces in types are required for "double precision", "character varying", etc.
# but an adversary could smuggle "integer DROP TABLE users" past the regex.
_TYPE_SQL_KEYWORDS = frozenset({
    "drop", "delete", "insert", "update", "select", "union", "alter",
    "create", "truncate", "exec", "execute", "grant", "revoke",
    "table", "database", "schema", "index", "from", "where", "into",
    "join", "having", "order", "group", "by",
    # [SECURITY] 'none' is not a SQL type — blocks 'type: null' str(None) bypass
    "none", "null",
})

# [SECURITY] Dangerous patterns in default values — SQL metacharacters
_DEFAULT_DANGEROUS = [";", "--", "/*", "*/", "\n", "\r", "\x00", "'", '"']


def validate_identifier(name: str) -> None:
    # [SECURITY] SQL identifier injection prevention — allowlist + blocklist
    if not name or not name.strip():
        raise SecurityError("SQL identifier cannot be empty")
    if len(name) > MAX_IDENTIFIER_LENGTH:
        raise SecurityError(
            f"Identifier too long: {len(name)} chars (max {MAX_IDENTIFIER_LENGTH})"
        )
    if not VALID_IDENTIFIER_RE.match(name):
        raise SecurityError(
            f"Invalid SQL identifier '{name[:30]}': "
            "only [a-zA-Z_][a-zA-Z0-9_]* allowed. "
            "Potential SQL injection attempt detected."
        )
    for pattern in _IDENTIFIER_CHAR_BLOCKLIST:
        if pattern.lower() in name.lower():
            raise SecurityError(
                f"Dangerous pattern '{pattern}' in identifier '{name[:30]}'"
            )
    # [SECURITY] Block MSSQL extended stored procedure prefix (xp_cmdshell etc.)
    # using prefix match only — substring match would reject legitimate names
    # like exp_date, my_exp_table, helper_exp_data.
    if name.lower().startswith("xp_"):
        raise SecurityError(
            f"Identifier '{name[:30]}' uses reserved 'xp_' prefix "
            "(MSSQL extended stored procedure namespace)."
        )


def validate_column_type(type_str: str) -> None:
    # [SECURITY] Column type allowlist — prevents type-field SQL injection
    if not type_str or not type_str.strip():
        raise SecurityError("Column type cannot be empty")
    # Limit raised to 128: "timestamp without time zone[]" + longer enum names
    if len(type_str) > 128:
        raise SecurityError(f"Column type too long: {len(type_str)} chars (max 128)")
    if not VALID_TYPE_RE.match(type_str.strip()):
        raise SecurityError(
            f"Invalid column type '{type_str[:40]}': only "
            "[a-zA-Z][a-zA-Z0-9 _]*(params)? allowed. "
            "Potential SQL injection attempt detected."
        )
    for pattern in _TYPE_DANGEROUS:
        if pattern in type_str:
            raise SecurityError(f"Dangerous pattern in column type '{type_str[:40]}'")
    # [SECURITY] Block SQL DDL/DML keywords in type fields. The regex allows
    # spaces (needed for "double precision", "character varying") but that
    # also admits "integer DROP TABLE users". Check each word individually.
    base = type_str.strip().split("(")[0]
    for word in base.lower().split():
        if word in _TYPE_SQL_KEYWORDS:
            raise SecurityError(
                f"SQL keyword '{word}' not allowed in column type '{type_str[:40]}'"
            )


def validate_default(value: str) -> None:
    # [SECURITY] Column default value — reject SQL metacharacters
    if len(value) > 256:
        raise SecurityError(f"Default value too long: {len(value)} chars (max 256)")
    for pattern in _DEFAULT_DANGEROUS:
        if pattern in value:
            raise SecurityError(f"Dangerous character in default value '{value[:40]}'")


def quote_identifier(name: str, dialect: str) -> str:
    validate_identifier(name)
    # [SECURITY] Reject unknown dialects explicitly — silent fallthrough would
    # produce MySQL-incompatible double-quoted identifiers for MySQL targets.
    if dialect not in SUPPORTED_DIALECTS:
        raise SecurityError(
            f"Unknown dialect '{dialect}'. Allowed: {SUPPORTED_DIALECTS}"
        )
    # [SECURITY] Dialect-aware quoting — prevents SQL injection via identifier names
    if dialect == "mysql":
        return f"`{name}`"
    return f'"{name}"'  # PostgreSQL and SQLite use double-quotes
