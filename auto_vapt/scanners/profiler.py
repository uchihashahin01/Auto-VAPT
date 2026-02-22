"""Target profiler — gathers intelligence about the scan target."""

from __future__ import annotations

import socket
from urllib.parse import urlparse

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import TargetInfo

log = get_logger(__name__)

# Common technology detection signatures in headers and responses
TECH_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "nginx": [{"header": "server", "value": "nginx"}],
    "Apache": [{"header": "server", "value": "apache"}],
    "IIS": [{"header": "server", "value": "microsoft-iis"}],
    "PHP": [{"header": "x-powered-by", "value": "php"}],
    "ASP.NET": [{"header": "x-powered-by", "value": "asp.net"}, {"header": "x-aspnet-version", "value": ""}],
    "Express.js": [{"header": "x-powered-by", "value": "express"}],
    "Django": [{"header": "x-frame-options", "value": "deny"}],
    "WordPress": [{"body": "wp-content"}, {"body": "wp-includes"}],
    "Drupal": [{"header": "x-generator", "value": "drupal"}, {"body": "drupal"}],
    "Joomla": [{"body": "/media/jui/"}, {"body": "joomla"}],
    "React": [{"body": "react"}, {"body": "_reactRoot"}],
    "Angular": [{"body": "ng-version"}, {"body": "ng-app"}],
    "Vue.js": [{"body": "vue"}, {"body": "__vue__"}],
    "jQuery": [{"body": "jquery"}],
    "Bootstrap": [{"body": "bootstrap"}],
    "Cloudflare": [{"header": "server", "value": "cloudflare"}, {"header": "cf-ray", "value": ""}],
}

# Common admin/sensitive paths for forced browsing
COMMON_PATHS = [
    "/admin", "/administrator", "/admin/login", "/wp-admin", "/wp-login.php",
    "/login", "/signin", "/auth", "/dashboard", "/panel",
    "/phpmyadmin", "/pma", "/adminer", "/phpinfo.php",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/api-docs",
    "/.env", "/.git/HEAD", "/.git/config", "/config.yml", "/config.json",
    "/backup", "/backup.sql", "/database.sql", "/dump.sql",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.well-known/security.txt",
    "/server-status", "/server-info", "/.htaccess", "/web.config",
    "/debug", "/trace", "/actuator", "/actuator/health", "/actuator/env",
    "/console", "/shell", "/cmd", "/exec",
    "/.DS_Store", "/Thumbs.db", "/.svn/entries",
]


async def profile_target(target_url: str, verify_ssl: bool = True) -> TargetInfo:
    """Profile a target URL to gather intelligence.

    Performs:
    - DNS resolution
    - HTTP method enumeration
    - Technology fingerprinting via headers and response body
    - robots.txt and sitemap.xml parsing
    - Common path discovery

    Args:
        target_url: The URL to profile.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        TargetInfo with gathered intelligence.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    info = TargetInfo(url=target_url, hostname=hostname)

    # DNS resolution
    try:
        ip = socket.gethostbyname(hostname)
        info.ip_address = ip
        log.info("dns_resolved", hostname=hostname, ip=ip)
    except socket.gaierror:
        log.warning("dns_resolution_failed", hostname=hostname)

    async with httpx.AsyncClient(
        verify=verify_ssl,
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        headers={"User-Agent": "Auto-VAPT/1.0 Security Scanner"},
    ) as client:
        # Main page request
        try:
            response = await client.get(target_url)
            info.headers = dict(response.headers)

            # Server header
            info.server = response.headers.get("server", "")
            info.powered_by = response.headers.get("x-powered-by", "")

            # Technology detection
            body_lower = response.text.lower() if response.text else ""
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

            detected_techs: list[str] = []
            for tech, signatures in TECH_SIGNATURES.items():
                for sig in signatures:
                    if "header" in sig:
                        header_val = headers_lower.get(sig["header"], "")
                        if sig["value"] == "" and header_val:
                            detected_techs.append(tech)
                            break
                        elif sig["value"] and sig["value"] in header_val:
                            detected_techs.append(tech)
                            break
                    elif "body" in sig:
                        if sig["body"] in body_lower:
                            detected_techs.append(tech)
                            break

            info.technologies = list(set(detected_techs))
            log.info("technologies_detected", techs=info.technologies)

        except httpx.RequestError as e:
            log.error("main_request_failed", error=str(e))

        # HTTP method enumeration
        try:
            options_resp = await client.options(target_url)
            allow = options_resp.headers.get("allow", "")
            if allow:
                info.http_methods = [m.strip() for m in allow.split(",")]
            else:
                # Probe common methods
                for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]:
                    try:
                        resp = await client.request(method, target_url)
                        if resp.status_code != 405:
                            info.http_methods.append(method)
                    except Exception:
                        pass
        except httpx.RequestError:
            pass

        # Robots.txt
        try:
            robots_resp = await client.get(f"{target_url.rstrip('/')}/robots.txt")
            if robots_resp.status_code == 200 and "user-agent" in robots_resp.text.lower():
                info.robots_txt = robots_resp.text
                log.info("robots_txt_found")
        except httpx.RequestError:
            pass

        # Sitemap.xml
        try:
            sitemap_resp = await client.get(f"{target_url.rstrip('/')}/sitemap.xml")
            if sitemap_resp.status_code == 200 and "<?xml" in sitemap_resp.text:
                # Extract URLs from sitemap (basic parsing)
                import re
                urls = re.findall(r"<loc>(.*?)</loc>", sitemap_resp.text)
                info.sitemap_urls = urls[:50]  # Limit to 50
                log.info("sitemap_found", url_count=len(info.sitemap_urls))
        except httpx.RequestError:
            pass

    return info
