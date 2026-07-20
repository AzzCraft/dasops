"""Regression test: generated product repos contain no residual angle-bracket placeholders."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER_RE = re.compile(r"<ORG>|<DAS_SUITE_REPO_URL>|<PRODUCT_REPO>")


class TestGeneratedProductPlaceholderScan(unittest.TestCase):
    """Scan dasops template artefacts for residual placeholders."""

    TEMPLATE_ROOT = REPO_ROOT / "templates" / "das-product"

    def test_no_placeholder_in_template_files(self):
        if not self.TEMPLATE_ROOT.exists():
            self.skipTest("dasops-product template directory not found")
        for path in self.TEMPLATE_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix in (".pyc", ".pyo", ".whl", ".egg"):
                continue
            try:
                content = path.read_text(errors="replace")
            except Exception:
                continue
            rel = path.relative_to(self.TEMPLATE_ROOT)
            with self.subTest(file=str(rel)):
                matches = PLACEHOLDER_RE.findall(content)
                self.assertEqual(
                    matches,
                    [],
                    f"template {rel} contains forbidden placeholder(s): {matches}",
                )


if __name__ == "__main__":
    unittest.main()
