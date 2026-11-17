"""Typed exceptions used across the prototype."""

from __future__ import annotations


class ObliRCAError(Exception):
    """Base class for all project errors."""


class ConfigurationError(ObliRCAError):
    pass


class ValidationError(ObliRCAError):
    pass


class ObligationError(ObliRCAError):
    pass


class EvidenceError(ObliRCAError):
    pass


class ToolError(ObliRCAError):
    pass


class BudgetExceeded(ObliRCAError):
    pass


class UnsupportedBackend(ToolError):
    pass


class ScenarioError(ObliRCAError):
    pass
