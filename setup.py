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
    version="1.0.0",
    description="DAS + OpenSpec factory tooling (CLI + templates)",
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    license="Apache-2.0",
    packages=find_packages(include=["dasops", "dasops.*"]),
    install_requires=["pyyaml>=6.0"],
    entry_points={"console_scripts": ["dasops=dasops.__main__:main"]},
    data_files=_data_files(),
)
