"""DAS-03-010 change container state machine.

Pure-Python, stdlib only. Validates allowed transitions and produces an
audit-trail entry for every change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

# Allowed transitions: source -> set of legal targets.
TRANSITIONS: dict[str, set[str]] = {
    "draft": {"ready", "blocked"},
    "ready": {"inProgress", "blocked"},
    "inProgress": {"done", "blocked"},
    "blocked": {"ready", "inProgress"},
    "done": {"verified", "rolledBack"},
    "verified": {"rolledBack"},
    "rolledBack": set(),
}

VALID_STATES = set(TRANSITIONS.keys())


class IllegalTransition(ValueError):
    """Raised when a state change is not permitted."""


@dataclass
class ChangeContainer:
    changeId: str
    state: str = "draft"
    title: str = ""
    owner: str = ""
    createdAt: str = ""
    updatedAt: str = ""
    history: list[dict] = field(default_factory=list)
    evidenceBundleId: str | None = None
    blockedReason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in VALID_STATES:
            raise ValueError(f"unknown state {self.state!r}")
        if not self.createdAt:
            self.createdAt = _now()
        if not self.updatedAt:
            self.updatedAt = self.createdAt

    def transition(self, target: str, *, actor: str = "", note: str = "") -> None:
        if target not in VALID_STATES:
            raise IllegalTransition(f"unknown target state {target!r}")
        allowed = TRANSITIONS[self.state]
        if target not in allowed:
            raise IllegalTransition(
                f"cannot move from {self.state!r} to {target!r}; "
                f"allowed: {sorted(allowed)}"
            )
        now = _now()
        self.history.append(
            {"from": self.state, "to": target, "at": now, "actor": actor, "note": note}
        )
        self.state = target
        self.updatedAt = now
        if target != "blocked":
            self.blockedReason = None

    def to_dict(self) -> dict:
        out: dict = {
            "changeId": self.changeId,
            "state": self.state,
            "createdAt": self.createdAt,
            "updatedAt": self.updatedAt,
            "history": list(self.history),
        }
        if self.title:
            out["title"] = self.title
        if self.owner:
            out["owner"] = self.owner
        if self.evidenceBundleId:
            out["evidenceBundleId"] = self.evidenceBundleId
        if self.blockedReason:
            out["blockedReason"] = self.blockedReason
        return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def reachable_states(start: str = "draft") -> set[str]:
    """Return the set of states reachable from ``start`` via legal transitions."""
    seen: set[str] = set()
    stack = [start]
    while stack:
        s = stack.pop()
        if s in seen:
            continue
        seen.add(s)
        stack.extend(TRANSITIONS[s])
    return seen


def validate_history(history: Iterable[dict]) -> list[str]:
    """Validate that a history list represents a legal walk through the FSM."""
    errors: list[str] = []
    last_to: str | None = None
    for i, entry in enumerate(history):
        src = entry.get("from")
        dst = entry.get("to")
        if src not in VALID_STATES or dst not in VALID_STATES:
            errors.append(f"entry {i}: unknown state(s)")
            continue
        if last_to is not None and src != last_to:
            errors.append(f"entry {i}: from={src!r} doesn't match prev to={last_to!r}")
        if dst not in TRANSITIONS[src]:
            errors.append(f"entry {i}: illegal transition {src!r} -> {dst!r}")
        last_to = dst
    return errors
