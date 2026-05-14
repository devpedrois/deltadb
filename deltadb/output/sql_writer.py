import os
import sys

from deltadb.security.path_safety import validate_output_path


def write_sql(sql: str, output_path: str | None = None) -> None:
    if output_path is None:
        sys.stdout.write(sql)
        return

    path = validate_output_path(output_path)
    # [SECURITY] Atomic write — prevents partial file on disk-full or process kill
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp_path.write_text(sql, encoding="utf-8")
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
