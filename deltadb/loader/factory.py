from pathlib import Path
from urllib.parse import urlparse

from deltadb.config import SUPPORTED_DIALECTS
from deltadb.exceptions import LoaderError
from deltadb.loader.base import BaseLoader
from deltadb.loader.db_loader import DbLoader
from deltadb.loader.yaml_loader import YamlLoader
from deltadb.security.path_safety import validate_input_path


def create_loader(source: str) -> BaseLoader:
    # [SECURITY] Use scheme-based detection instead of substring "://" check.
    # A file path like "./schemas/report://export.yml" contains "://" but is
    # not a database URL — urlparse correctly identifies it as having no scheme.
    parsed = urlparse(source)
    scheme = parsed.scheme.split("+")[0]  # handle "postgresql+psycopg2://..."
    if scheme in SUPPORTED_DIALECTS:
        return DbLoader(source)
    p = Path(source)
    if p.suffix in (".yml", ".yaml"):
        # [SECURITY] Path traversal prevention — reject '..' and absolute paths
        validate_input_path(source)
        if not p.exists():
            raise LoaderError(f"Schema file not found: {source}")
        return YamlLoader(str(p))
    raise LoaderError(
        f"Cannot determine loader for '{source}'. Expected URL or .yml file."
    )
