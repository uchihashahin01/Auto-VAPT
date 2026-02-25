"""Plugin system for loading custom scanner modules at runtime."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from auto_vapt.logger import get_logger
from auto_vapt.scanners.base import BaseScanner, register_scanner, get_registered_scanners

log = get_logger(__name__)


def load_plugins(plugin_dir: str | Path) -> int:
    """Discover and load custom scanner plugins from a directory.

    Any .py file in the directory that defines a subclass of BaseScanner
    will be automatically registered in the scanner registry.

    Args:
        plugin_dir: Path to directory containing plugin .py files.

    Returns:
        Number of plugins successfully loaded.
    """
    plugin_path = Path(plugin_dir)
    if not plugin_path.is_dir():
        log.debug("plugin_dir_not_found", path=str(plugin_path))
        return 0

    before = set(get_registered_scanners().keys())
    loaded = 0

    for py_file in sorted(plugin_path.glob("*.py")):
        if py_file.name.startswith("_"):
            continue

        module_name = f"autovapt_plugin_{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Auto-register any BaseScanner subclasses with @register_scanner
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseScanner)
                        and attr is not BaseScanner
                        and hasattr(attr, "scanner_id")
                        and attr.scanner_id
                    ):
                        if attr.scanner_id not in get_registered_scanners():
                            register_scanner(attr)

                loaded += 1
                log.info("plugin_loaded", file=py_file.name, module=module_name)
        except Exception as e:
            log.error("plugin_load_failed", file=py_file.name, error=str(e))

    after = set(get_registered_scanners().keys())
    new_scanners = after - before
    if new_scanners:
        log.info("plugins_registered", scanners=list(new_scanners))

    return loaded
