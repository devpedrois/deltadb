MAX_YAML_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
MAX_IDENTIFIER_LENGTH = 128
# [SECURITY] Anchor-expansion DoS — limits in-memory object count after safe_load
MAX_TABLES = 500
MAX_COLUMNS_PER_TABLE = 300
SUPPORTED_DIALECTS = ("postgresql", "mysql", "sqlite")
SUPPORTED_OUTPUT_EXTENSIONS = (".sql", ".json", ".yml", ".yaml")
DEFAULT_RENAME_THRESHOLD = 0.7
CONNECTION_TIMEOUT = 10
