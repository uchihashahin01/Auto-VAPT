"""Scanner package — auto-discovers and loads all scanner modules."""

from auto_vapt.scanners.base import (
    BaseScanner,
    get_registered_scanners,
    get_scanner,
    register_scanner,
)

# Import all scanner modules to trigger registration
from auto_vapt.scanners import (  # noqa: F401
    injection,
    broken_access,
    crypto,
    misconfig,
    vulnerable_components,
    auth_failures,
    zap_scanner,
    insecure_design,
    data_integrity,
    logging_failures,
    ssrf,
)

__all__ = [
    "BaseScanner",
    "register_scanner",
    "get_registered_scanners",
    "get_scanner",
]
