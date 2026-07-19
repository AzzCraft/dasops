"""dasops.prompts — Render prompt templates for Orchestrator/Worker roles.

Provides template rendering for the dasops prompt command.
"""

from __future__ import annotations

from pathlib import Path


def _render(template: str, mapping: dict[str, str]) -> str:
    """Replace {{key}} placeholders in a template string."""
    out = template
    for k, v in mapping.items():
        out = out.replace(f"{{{{{k}}}}}", v)
    return out


def load_prompt_template(factory_root: Path, role: str) -> str:
    """Load a prompt template by role name.

    Looks for ``templates/prompts/<role>.md`` under *factory_root*.
    Returns the raw template text, or a fallback prompt.
    """
    candidate = factory_root / "templates" / "prompts" / f"{role}.md"
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")
    return f"# {role.title()} Prompt\n\nNo template found at {candidate}.\n"


def render_prompt(factory_root: Path, role: str, mapping: dict[str, str]) -> str:
    """Load and render a prompt template."""
    template = load_prompt_template(factory_root, role)
    return _render(template, mapping)


__all__ = ["load_prompt_template", "render_prompt"]
