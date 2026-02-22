"""Configuration system for Auto-VAPT scans."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from auto_vapt.models import Severity


class ScannerConfig(BaseModel):
    """Configuration for individual scanner modules."""

    enabled: bool = True
    timeout: int = Field(default=300, ge=10, le=3600, description="Scanner timeout in seconds")
    threads: int = Field(default=5, ge=1, le=50, description="Concurrent threads per scanner")
    custom_payloads: str | None = Field(default=None, description="Path to custom payload file")


class TargetConfig(BaseModel):
    """Target specification."""

    url: str
    scope: list[str] = Field(default_factory=list, description="Additional in-scope URLs/patterns")
    exclude: list[str] = Field(default_factory=list, description="URL patterns to exclude")
    auth: AuthConfig | None = None


class AuthConfig(BaseModel):
    """Authentication configuration for authenticated scanning."""

    type: str = Field(default="none", description="Auth type: none, basic, bearer, cookie, form")
    username: str = ""
    password: str = ""
    token: str = ""
    login_url: str = ""
    cookie: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class ReportConfig(BaseModel):
    """Reporting configuration."""

    output_dir: str = Field(default="./reports", description="Output directory for reports")
    formats: list[str] = Field(
        default_factory=lambda: ["html", "json"],
        description="Report formats: html, json, pdf, sarif",
    )
    include_evidence: bool = Field(default=True, description="Include request/response evidence")
    include_remediation: bool = Field(default=True, description="Include remediation steps")
    company_name: str = ""
    company_logo: str = ""


class CIConfig(BaseModel):
    """CI/CD integration configuration."""

    enabled: bool = False
    fail_on: Severity = Field(
        default=Severity.HIGH, description="Minimum severity to fail the pipeline"
    )
    sarif_output: bool = Field(default=True, description="Generate SARIF output for code scanning")
    comment_pr: bool = Field(default=False, description="Post results as PR comment")
    max_allowed: dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 10, "LOW": 50},
        description="Maximum allowed vulnerabilities per severity",
    )


class ScanConfig(BaseModel):
    """Root scan configuration."""

    profile: str = Field(default="default", description="Scan profile name")
    target: TargetConfig
    scanners: dict[str, ScannerConfig] = Field(
        default_factory=lambda: {
            "injection": ScannerConfig(),
            "broken_access": ScannerConfig(),
            "crypto": ScannerConfig(),
            "misconfig": ScannerConfig(),
            "vulnerable_components": ScannerConfig(),
            "auth_failures": ScannerConfig(),
        }
    )
    report: ReportConfig = Field(default_factory=ReportConfig)
    ci: CIConfig = Field(default_factory=CIConfig)
    global_timeout: int = Field(
        default=1800, ge=60, le=7200, description="Global scan timeout in seconds"
    )
    max_concurrent_scanners: int = Field(
        default=3, ge=1, le=10, description="Max scanners running in parallel"
    )
    rate_limit: int = Field(
        default=10, ge=1, le=100, description="Max requests per second to target"
    )
    user_agent: str = Field(
        default="Auto-VAPT/1.0 Security Scanner",
        description="User-Agent string for requests",
    )
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    max_depth: int = Field(default=3, ge=1, le=10, description="Max crawl depth")
    max_pages: int = Field(default=100, ge=10, le=500, description="Max pages to crawl")

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        """Validate profile name."""
        allowed = {"default", "quick", "full", "api", "ci"}
        if v not in allowed:
            raise ValueError(f"Profile must be one of: {', '.join(allowed)}")
        return v


def load_config(config_path: str | Path) -> ScanConfig:
    """Load and validate scan configuration from a YAML file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Validated ScanConfig instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config validation fails.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    return ScanConfig(**raw)


def create_config_from_args(
    target_url: str,
    profile: str = "default",
    output_dir: str = "./reports",
    formats: list[str] | None = None,
    ci_mode: bool = False,
    rate_limit: int = 10,
    timeout: int = 1800,
    verify_ssl: bool = True,
) -> ScanConfig:
    """Create a ScanConfig from CLI arguments.

    Args:
        target_url: Target URL to scan.
        profile: Scan profile name.
        output_dir: Report output directory.
        formats: Report formats.
        ci_mode: Enable CI/CD mode.
        rate_limit: Request rate limit.
        timeout: Global timeout in seconds.
        verify_ssl: Whether to verify SSL certs.

    Returns:
        Configured ScanConfig instance.
    """
    config = ScanConfig(
        profile=profile,
        target=TargetConfig(url=target_url),
        report=ReportConfig(
            output_dir=output_dir,
            formats=formats or ["html", "json"],
        ),
        ci=CIConfig(enabled=ci_mode, sarif_output=ci_mode),
        rate_limit=rate_limit,
        global_timeout=timeout,
        verify_ssl=verify_ssl,
    )

    # Apply profile-specific overrides
    if profile == "quick":
        config.max_depth = 1
        config.global_timeout = min(timeout, 600)
        config.scanners = {
            "injection": ScannerConfig(timeout=120),
            "misconfig": ScannerConfig(timeout=120),
        }
    elif profile == "full":
        config.max_depth = 5
        config.max_concurrent_scanners = 5
    elif profile == "api":
        config.scanners = {
            "injection": ScannerConfig(),
            "broken_access": ScannerConfig(),
            "auth_failures": ScannerConfig(),
        }
    elif profile == "ci":
        config.ci.enabled = True
        config.ci.sarif_output = True
        config.max_depth = 2
        config.global_timeout = min(timeout, 900)

    return config
