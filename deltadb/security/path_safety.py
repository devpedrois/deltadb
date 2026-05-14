from pathlib import Path

from deltadb.config import SUPPORTED_OUTPUT_EXTENSIONS
from deltadb.exceptions import SecurityError


def _reject_symlink_escape(p: Path, label: str) -> None:
    # [SECURITY] Symlink traversal prevention — a symlink pointing outside
    # the working directory bypasses the '../' and absolute-path checks.
    # Resolve follows all symlinks; relative_to verifies containment in cwd.
    resolved = p.resolve()
    cwd = Path.cwd().resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        raise SecurityError(
            f"Symlink traversal detected: {label} '{p}' resolves to '{resolved}' "
            "which is outside the working directory."
        )


def validate_input_path(path_str: str) -> None:
    """Reject path traversal in schema input file paths.

    # [SECURITY] Path traversal prevention for input files — an attacker
    # passing '../../etc/secrets.yml' as schema source must be blocked.
    """
    p = Path(path_str)
    if p.is_absolute():
        raise SecurityError(
            f"Absolute input path not allowed: '{path_str}'. Use relative paths only."
        )
    if ".." in p.parts:
        raise SecurityError(
            f"Path traversal detected in input path: '{path_str}' contains '..'"
        )
    # [SECURITY] Always resolve and verify containment in cwd — prevents TOCTOU symlink
    # traversal where a symlink is created between the check and the open() call.
    try:
        resolved = p.resolve()
        cwd = Path.cwd().resolve()
        resolved.relative_to(cwd)
    except ValueError:
        raise SecurityError(
            f"Path traversal detected: input path '{path_str}' resolves outside the working directory."
        )
    # [SECURITY] Explicit symlink check on existing files as a redundant layer
    if p.exists():
        _reject_symlink_escape(p, "input path")


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
    # [SECURITY] Case-sensitive extension check — .SQL and .JSON are not allowed;
    # accepting uppercase silently would bypass the routing logic in cli.py.
    if p.suffix not in SUPPORTED_OUTPUT_EXTENSIONS:
        raise SecurityError(
            f"Unsupported output extension '{p.suffix}'. "
            f"Allowed: {SUPPORTED_OUTPUT_EXTENSIONS}"
        )
    # [SECURITY] Symlink check before mkdir — detect symlink traversal in parent
    # directories before we create anything on disk.
    if p.parent != Path(".") and p.parent.exists():
        _reject_symlink_escape(p.parent, "output directory")
    if p.exists():
        _reject_symlink_escape(p, "output path")
    p.parent.mkdir(parents=True, exist_ok=True)
    # [SECURITY] Post-mkdir check — a race window exists between the checks above
    # and mkdir; verify again after creation.
    _reject_symlink_escape(p.parent.resolve(), "output directory (post-mkdir)")
    return p
