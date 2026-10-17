"""DAS — `dasops create` command: scaffold a new ChangeContainer."""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass

TASK_ID = "DAS-DASOPS-CREATE"


@dataclass
class CreateResult:
    ok: bool
    path: str
    changeId: str

    def to_dict(self) -> dict:
        return {"schemaVersion": 1, "task": TASK_ID, "ok": self.ok,
                "path": self.path, "changeId": self.changeId}


def create_change(workspace: pathlib.Path, change_id: str, *, title: str = "",
                  scope: str = "general") -> CreateResult:
    if not change_id:
        raise ValueError("changeId required")
    out_dir = workspace / "changes" / change_id
    if out_dir.exists():
        raise FileExistsError(f"{out_dir} already exists")
    out_dir.mkdir(parents=True)
    cc = {
        "schemaVersion": 1,
        "id": change_id,
        "title": title or change_id,
        "scope": scope,
        "status": "draft",
        "tasks": [],
        "evidence": [],
    }
    (out_dir / "change.json").write_text(json.dumps(cc, indent=2) + "\n",
                                         encoding="utf-8")
    (out_dir / "README.md").write_text(f"# {title or change_id}\n\nChange container `{change_id}`.\n",
                                       encoding="utf-8")
    return CreateResult(ok=True, path=str(out_dir), changeId=change_id)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        sys.stderr.write("usage: dasops create <workspace> <changeId> [title]\n"); return 2
    workspace = pathlib.Path(argv[1]).resolve()
    change_id = argv[2]
    title = argv[3] if len(argv) > 3 else ""
    try:
        res = create_change(workspace, change_id, title=title)
    except (ValueError, FileExistsError) as exc:
        json.dump({"ok": False, "error": str(exc)}, sys.stdout, indent=2)
        sys.stdout.write("\n"); return 1
    json.dump(res.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
