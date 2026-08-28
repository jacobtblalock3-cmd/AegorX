"""Management-plane exceptions."""

from __future__ import annotations


class ManagementError(RuntimeError):
    pass


class CommandRejected(ManagementError):
    pass


class EnrollmentError(ManagementError):
    pass


__all__ = ["CommandRejected", "EnrollmentError", "ManagementError"]
