"""Run locking utilities.

Tuân thủ Rule 8.2 (<domain>_utils.py).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from .errors import RunLockError

try:  # Windows
    import msvcrt
    _HAVE_MSVCRT = True
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]
    _HAVE_MSVCRT = False

try:  # POSIX
    import fcntl
    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
    _HAVE_FCNTL = False


class RunLock:
    """Exclusive, OS backed lock on a run directory."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._handle: Optional[Any] = None
        self._acquired = False

    def acquire(self, blocking: bool = False) -> bool:
        """Try to acquire the lock. Returns False when another process holds it."""
        if self._acquired:
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+b")
        try:
            if _HAVE_MSVCRT:
                handle.seek(0)
                if not handle.read(1):
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
                msvcrt.locking(handle.fileno(), mode, 1)
            elif _HAVE_FCNTL:  # pragma: no cover - POSIX
                flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
                fcntl.flock(handle.fileno(), flags)
            else:  # pragma: no cover - exotic platform
                raise RunLockError("no operating system file lock available on this platform")
        except OSError as exc:
            handle.close()
            if blocking:
                raise RunLockError(f"cannot acquire run lock {self.path}: {exc}") from exc
            return False
        self._handle = handle
        self._acquired = True
        return True

    def release(self) -> None:
        if not self._acquired or self._handle is None:
            return
        handle = self._handle
        try:
            if _HAVE_MSVCRT:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            elif _HAVE_FCNTL:  # pragma: no cover - POSIX
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:  # pragma: no cover - defensive
            pass
        finally:
            handle.close()
            self._handle = None
            self._acquired = False

    @property
    def acquired(self) -> bool:
        return self._acquired

    def __enter__(self) -> "RunLock":
        if not self.acquire():
            raise RunLockError(f"run is locked by another process: {self.path}")
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.release()
