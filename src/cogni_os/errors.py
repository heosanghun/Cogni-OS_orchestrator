"""Cogni-OS Exception classes."""

class CogniError(Exception):
    """Base exception for Cogni-OS errors."""

class ConfigurationError(CogniError):
    """Raised when workspace or agent configuration is invalid."""

class StateError(CogniError):
    """Raised when an operation violates workspace state invariants."""

class TransitionError(StateError):
    """Raised when a task transition is illegal."""

class LeaseError(StateError):
    """Raised when a lease is missing, expired, or invalid."""

class AuthorizationError(StateError):
    """Raised when an actor lacks permission for an operation."""

class IntegrityError(StateError):
    """Raised when ledger or snapshot integrity verification fails."""

class EvidenceError(StateError):
    """Raised when evidence verification fails or manifests are invalid."""

class AdapterError(CogniError):
    """Raised when an external agent command fails or violates workspace bounds."""

class LockTimeout(CogniError):
    """Raised when acquiring a file lock times out."""
