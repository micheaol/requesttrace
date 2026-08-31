"""The CLI exit code contract (PRD §11) and the exceptions that map to it."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Deterministic process exit codes consumed by CI/CD pipelines."""

    SUCCESS = 0
    POLICY_BREACH = 1
    INVALID_INPUT = 2
    SCAN_EXECUTION_FAILED = 3
    INTERNAL_ERROR = 4


class RequestTraceError(Exception):
    """Base class for errors that carry an explicit process exit code."""

    exit_code: ExitCode = ExitCode.INTERNAL_ERROR


class InvalidInputError(RequestTraceError):
    """Invalid command, target or configuration (exit 2)."""

    exit_code = ExitCode.INVALID_INPUT


class ScanExecutionError(RequestTraceError):
    """Network/scan execution failed before a valid assessment completed (exit 3)."""

    exit_code = ExitCode.SCAN_EXECUTION_FAILED
