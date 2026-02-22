"""Base scanner class and scanner registry."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from auto_vapt.config import ScannerConfig
from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, ScanResult, Vulnerability

log = get_logger(__name__)

# Global scanner registry
_SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Decorator to register a scanner class in the global registry."""
    _SCANNER_REGISTRY[cls.scanner_id] = cls
    log.debug("scanner_registered", scanner_id=cls.scanner_id, name=cls.scanner_name)
    return cls


def get_registered_scanners() -> dict[str, type[BaseScanner]]:
    """Get all registered scanner classes."""
    return _SCANNER_REGISTRY.copy()


def get_scanner(scanner_id: str) -> type[BaseScanner] | None:
    """Get a scanner class by its ID."""
    return _SCANNER_REGISTRY.get(scanner_id)


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners.

    Each scanner targets a specific OWASP category and implements
    the `scan()` method to detect vulnerabilities.

    Subclasses must define:
        - scanner_id: Unique identifier for the scanner
        - scanner_name: Human-readable name
        - owasp_category: OWASP Top 10 category this scanner covers
        - scan(): The actual scanning logic

    Usage:
        @register_scanner
        class MyScanner(BaseScanner):
            scanner_id = "my_scanner"
            scanner_name = "My Custom Scanner"
            owasp_category = OWASPCategory.A03_INJECTION

            async def scan(self, target_url, **kwargs):
                # scanning logic here
                self.add_vulnerability(Vulnerability(...))
    """

    scanner_id: ClassVar[str] = ""
    scanner_name: ClassVar[str] = ""
    owasp_category: ClassVar[OWASPCategory]

    def __init__(self, config: ScannerConfig | None = None) -> None:
        """Initialize the scanner with configuration.

        Args:
            config: Scanner-specific configuration. Uses defaults if None.
        """
        self.config = config or ScannerConfig()
        self.vulnerabilities: list[Vulnerability] = []
        self.errors: list[str] = []
        self.metadata: dict[str, Any] = {}
        self._start_time: float = 0
        self._cancelled = False

    async def execute(self, target_url: str, **kwargs: Any) -> ScanResult:
        """Execute the scanner and return results.

        This wraps the scan() method with timing, error handling,
        and timeout enforcement.

        Args:
            target_url: The URL to scan.
            **kwargs: Additional arguments passed to scan().

        Returns:
            ScanResult with all discovered vulnerabilities.
        """
        self._start_time = time.time()
        log.info(
            "scanner_started",
            scanner=self.scanner_name,
            target=target_url,
            timeout=self.config.timeout,
        )

        try:
            await asyncio.wait_for(
                self.scan(target_url, **kwargs),
                timeout=self.config.timeout,
            )
        except asyncio.TimeoutError:
            self.errors.append(f"Scanner timed out after {self.config.timeout}s")
            log.warning("scanner_timeout", scanner=self.scanner_name)
        except asyncio.CancelledError:
            self._cancelled = True
            log.info("scanner_cancelled", scanner=self.scanner_name)
        except Exception as e:
            self.errors.append(f"Scanner error: {str(e)}")
            log.error("scanner_error", scanner=self.scanner_name, error=str(e))

        duration = time.time() - self._start_time
        from datetime import datetime, timezone

        result = ScanResult(
            scanner_name=self.scanner_name,
            owasp_category=self.owasp_category,
            completed_at=datetime.now(timezone.utc),
            duration_seconds=round(duration, 2),
            vulnerabilities=self.vulnerabilities,
            errors=self.errors,
            metadata=self.metadata,
        )

        log.info(
            "scanner_completed",
            scanner=self.scanner_name,
            vulns_found=len(self.vulnerabilities),
            duration=f"{duration:.2f}s",
            errors=len(self.errors),
        )

        return result

    @abstractmethod
    async def scan(self, target_url: str, **kwargs: Any) -> None:
        """Perform the actual vulnerability scan.

        Subclasses must implement this method. Use self.add_vulnerability()
        to register discovered vulnerabilities.

        Args:
            target_url: The URL to scan.
            **kwargs: Additional arguments (e.g., target_info, http_client).
        """
        ...

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Register a discovered vulnerability.

        Args:
            vuln: The vulnerability to add.
        """
        vuln.scanner = self.scanner_name
        self.vulnerabilities.append(vuln)
        log.info(
            "vulnerability_found",
            scanner=self.scanner_name,
            title=vuln.title,
            severity=vuln.severity.value,
            cvss=vuln.cvss_score,
        )

    def add_error(self, message: str) -> None:
        """Register a scanner error.

        Args:
            message: Error description.
        """
        self.errors.append(message)
        log.warning("scanner_error_added", scanner=self.scanner_name, error=message)

    @property
    def is_cancelled(self) -> bool:
        """Check if the scanner has been cancelled."""
        return self._cancelled

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time since scan started."""
        if self._start_time == 0:
            return 0.0
        return time.time() - self._start_time
