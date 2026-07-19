"""dasops.status — Change and task status display.

Thin façade re-exporting ``print_status`` from the scaffold module.
"""

from __future__ import annotations

from .scaffold import print_status

__all__ = ["print_status"]
