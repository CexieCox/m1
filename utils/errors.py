"""Error types and process exit codes for LoaderFilter.

Tuân thủ Rule 9: PascalCase + Error cho exception.
"""

from __future__ import annotations

from typing import Any, Optional

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_INTEGRITY = 4
EXIT_INTERRUPT = 130


class LoaderFilterError(Exception):
    """Base class for every error that maps to a defined exit code."""

    exit_code = EXIT_USAGE
    error_code = "loaderfilter_error"

    def __init__(self, message: str, *, error_code: Optional[str] = None, details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        if error_code:
            self.error_code = error_code
        self.details = details


class UsageError(LoaderFilterError):
    exit_code = EXIT_USAGE
    error_code = "usage_error"


class ConfigError(LoaderFilterError):
    exit_code = EXIT_USAGE
    error_code = "config_error"


class TaxonomyError(LoaderFilterError):
    exit_code = EXIT_USAGE
    error_code = "taxonomy_error"


class LabelDataError(LoaderFilterError):
    exit_code = EXIT_USAGE
    error_code = "label_data_error"


class RunLockError(LoaderFilterError):
    exit_code = EXIT_USAGE
    error_code = "run_locked"


class CapabilityError(LoaderFilterError):
    """Raised when a requested capability is not implemented by this version."""

    exit_code = EXIT_INTEGRITY
    error_code = "capability_not_implemented"


class IntegrityError(LoaderFilterError):
    exit_code = EXIT_INTEGRITY
    error_code = "integrity_error"


class ReportProcessingError(Exception):
    """Per-report failure. Never aborts the batch; recorded with an error code."""

    def __init__(self, error_code: str, message: str, *, fatal: bool = True, details: Optional[Any] = None):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.fatal = fatal
        self.details = details


class ResourceLimitError(ReportProcessingError):
    def __init__(self, message: str, *, limit: Optional[str] = None, observed: Optional[Any] = None):
        super().__init__("resource_limit", message, fatal=True, details={"limit": limit, "observed": observed})
        self.limit = limit
        self.observed = observed


class SourceChangedError(ReportProcessingError):
    def __init__(self, message: str):
        super().__init__("source_changed", message, fatal=True)


class UnsupportedReportError(ReportProcessingError):
    def __init__(self, message: str):
        super().__init__("unsupported_schema", message, fatal=True)
