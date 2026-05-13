import sys

from deltadb.security.path_safety import validate_output_path


def write_sql(sql: str, output_path: str | None = None) -> None:
    if output_path is None:
        sys.stdout.write(sql)
        return

    path = validate_output_path(output_path)
    path.write_text(sql, encoding="utf-8")
