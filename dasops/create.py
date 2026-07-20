"""dasops.create — Product-repo creation and initialization.

Thin façade that re-exports ``create_product_repo`` and ``init_repo`` from
the repo-factory module so callers can ``from dasops.create import …``.
"""

from __future__ import annotations

from .repo_factory import create_product_repo, init_repo

__all__ = ["create_product_repo", "init_repo"]
