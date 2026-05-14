import json
import os

from deltadb.diff.changes import Change
from deltadb.security.path_safety import validate_output_path


def _change_to_dict(change: Change) -> dict:
    return {
        "type": change.type.value,
        "table": change.table,
        "column": change.column,
        "destructive": change.destructive,
        "detail": change.detail,
    }


def export_json(changes: list[Change], output_path: str) -> None:
    path = validate_output_path(output_path)
    payload = [_change_to_dict(c) for c in changes]
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    # [SECURITY] Atomic write — prevents partial file on disk-full or process kill
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
