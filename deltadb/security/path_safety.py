from pathlib import Path

from deltadb.config import SUPPORTED_OUTPUT_EXTENSIONS
from deltadb.exceptions import SecurityError


def validate_output_path(path_str: str) -> Path:
    p = Path(path_str)
    # [SECURITY] Absolute paths escape the working directory without needing '..'.
    # /etc/evil.sql has a valid extension and no '..' but is still a traversal.
    if p.is_absolute():
        raise SecurityError(
            f"Absolute path not allowed: '{path_str}'. Use relative paths only."
        )
    # [SECURITY] Path traversal prevention — reject '..' components
    if ".." in p.parts:
        raise SecurityError(f"Path traversal detected: '{path_str}' contains '..'")
    if p.suffix not in SUPPORTED_OUTPUT_EXTENSIONS:
        raise SecurityError(
            f"Unsupported output extension '{p.suffix}'. "
            f"Allowed: {SUPPORTED_OUTPUT_EXTENSIONS}"
        )
    # [SECURITY] mkdir avoids symlink-based traversal since we already rejected '..'
    p.parent.mkdir(parents=True, exist_ok=True)
    return p
