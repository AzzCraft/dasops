from __future__ import annotations

from pathlib import Path
import re

from setuptools import setup


def _data_files() -> list[tuple[str, list[str]]]:
    files: list[tuple[str, list[str]]] = []
    template_root = Path("templates") / "das-product"
    if template_root.exists():
        by_dest: dict[str, list[str]] = {}
        for path in sorted(template_root.rglob("*")):
            if path.is_file():
                by_dest.setdefault(path.parent.as_posix(), []).append(path.as_posix())
        files.extend(sorted(by_dest.items()))
    return files


PROJECT_TOML = Path("pyproject.toml").read_text(encoding="utf-8")


def _project_string(key: str) -> str:
    match = re.search(rf"^{re.escape(key)}\s*=\s*\"([^\"]+)\"$", PROJECT_TOML, re.M)
    if match is None:
        raise RuntimeError(f"missing [project] {key} in pyproject.toml")
    return match.group(1)


def _project_dependencies() -> list[str]:
    match = re.search(r"^dependencies\s*=\s*\[([^]]*)\]$", PROJECT_TOML, re.M | re.S)
    if match is None:
        raise RuntimeError("missing [project] dependencies in pyproject.toml")
    return re.findall(r'"([^"]+)"', match.group(1))


setup(
    name=_project_string("name"),
    version=_project_string("version"),
    description=_project_string("description"),
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=_project_string("requires-python"),
    license="Apache-2.0",
    packages=["dasops", "dasops.lock"],
    install_requires=_project_dependencies(),
    entry_points={"console_scripts": ["dasops=dasops.__main__:main"]},
    data_files=_data_files(),
)
