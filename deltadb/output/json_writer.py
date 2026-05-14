import json

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
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
