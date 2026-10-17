from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup


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


setup(
    name="dasops",
    version=Path("VERSION").read_text(encoding="utf-8").strip(),
    description="DAS + OpenSpec factory tooling (CLI + templates)",
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    license="Apache-2.0",
    packages=find_packages(include=["dasops", "dasops.*"]),
    install_requires=["pyyaml>=6.0", "jsonschema>=4.21,<5", "rfc3339-validator>=0.1.4,<0.2", "rfc8785==0.1.4"],
    include_package_data=True,
    package_data={
        "dasops.protected": ["schemas/*.json"],
        "dasops.protected.sqlite": ["*.sql"],
        "dasops.bootstrap": ["schemas/*.json"],
        "dasops.standards_contracts": ["*.schema.json"],
    },
    entry_points={
        "console_scripts": [
            "dasops=dasops.__main__:main",
            "das-bootstrap-publisher=dasops.bootstrap_cli:publisher_main",
        ]
    },
    data_files=_data_files(),
)
