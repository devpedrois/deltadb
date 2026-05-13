from pathlib import Path

from deltadb.exceptions import LoaderError
from deltadb.loader.base import BaseLoader
from deltadb.loader.db_loader import DbLoader
from deltadb.loader.yaml_loader import YamlLoader
from deltadb.security.path_safety import validate_input_path


def create_loader(source: str) -> BaseLoader:
    if "://" in source:
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
