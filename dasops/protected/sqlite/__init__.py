"""Versioned coordination primitives; deployment activation remains separate."""
from .store import CoordinationDatabase, CoordinationError, TaskKey
from .authority import AuthorityRoute
from .legacy import import_legacy

__all__ = ['CoordinationDatabase', 'CoordinationError', 'TaskKey', 'AuthorityRoute', 'import_legacy']
