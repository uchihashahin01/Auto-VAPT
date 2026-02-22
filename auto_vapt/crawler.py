"""Async web crawler — discovers pages, forms, and parameters across a target site.

The crawler performs breadth-first traversal of internal links up to a configurable
depth, extracting forms, input parameters, URLs with query strings, and JavaScript
endpoints. Results feed directly into scanners for comprehensive coverage.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

import httpx
from bs4 import BeautifulSoup

from auto_vapt.logger import get_logger

log = get_logger(__name__)


@dataclass
class FormData:
    """Represents a discovered HTML form."""

    url: str
    action: str
    method: str
    inputs: list[dict[str, str]] = field(default_factory=list)

    @property
    def parameters(self) -> list[str]:
        """Get all named input parameters."""
        return [i["name"] for i in self.inputs if i.get("name")]


@dataclass
class CrawlResult:
    """Aggregated results from a crawl session."""

    discovered_urls: set[str] = field(default_factory=set)
    forms: list[FormData] = field(default_factory=list)
    parameters: set[str] = field(default_factory=set)
    js_endpoints: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    comments: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_pages(self) -> int:
        return len(self.discovered_urls)

    @property
    def unique_params(self) -> list[str]:
        return sorted(self.parameters)

    def summary(self) -> dict[str, int]:
        return {
            "pages": self.total_pages,
            "forms": len(self.forms),
            "parameters": len(self.parameters),
            "js_endpoints": len(self.js_endpoints),
            "emails": len(self.emails),
            "comments": len(self.comments),
        }


class WebCrawler:
    """Async BFS web crawler with form and parameter extraction.

    Features:
    - Breadth-first traversal with configurable depth
    - Same-origin enforcement
    - Form discovery with input type detection
    - URL parameter extraction
    - JavaScript endpoint extraction from inline scripts
    - HTML comment extraction (often leak sensitive info)
    - Email address harvesting
    - Rate-limiting via configurable concurrency
    - Exclusion patterns for logout/static/binary paths
    """

    DEFAULT_EXCLUDE = [
        r".*\.(jpg|jpeg|png|gif|svg|ico|webp|bmp|tiff)$",
        r".*\.(css|js|woff|woff2|ttf|eot|otf)$",
        r".*\.(pdf|doc|docx|xls|xlsx|zip|tar|gz|rar)$",
        r".*\.(mp3|mp4|avi|mov|wmv|flv)$",
        r".*/logout.*",
        r".*/signout.*",
        r".*/disconnect.*",
        r".*#.*",
        r".*javascript:.*",
        r".*mailto:.*",
        r".*tel:.*",
    ]

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 100,
        concurrency: int = 10,
        rate_limit: float = 0.1,
        exclude_patterns: list[str] | None = None,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        user_agent: str = "Auto-VAPT/1.0 Security Scanner",
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent

        self.exclude_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (exclude_patterns or self.DEFAULT_EXCLUDE)
        ]

        self._visited: set[str] = set()
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._result = CrawlResult()
        self._base_domain: str = ""
        self._base_scheme: str = ""
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(concurrency)

    async def crawl(self, start_url: str, http_client: httpx.AsyncClient | None = None) -> CrawlResult:
        """Crawl starting from the given URL.

        Args:
            start_url: The seed URL to begin crawling from.
            http_client: Optional shared HTTP client.

        Returns:
            CrawlResult with all discovered pages, forms, and parameters.
        """
        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc
        self._base_scheme = parsed.scheme

        # Normalize and seed the queue
        seed = self._normalize_url(start_url)
        self._queue.put_nowait((seed, 0))

        log.info("crawl_started", target=start_url, max_depth=self.max_depth, max_pages=self.max_pages)

        client = http_client or httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=httpx.Timeout(10.0),
            follow_redirects=self.follow_redirects,
            headers={"User-Agent": self.user_agent},
        )

        try:
            workers = [asyncio.create_task(self._worker(client)) for _ in range(self.concurrency)]
            await self._queue.join()

            # Signal workers to stop
            for _ in workers:
                self._queue.put_nowait(("__STOP__", -1))
            await asyncio.gather(*workers)

        except Exception as e:
            self._result.errors.append(f"Crawl error: {e}")
            log.error("crawl_error", error=str(e))
        finally:
            if http_client is None:
                await client.aclose()

        self._result.discovered_urls = self._visited.copy()
        summary = self._result.summary()
        log.info("crawl_completed", **summary)

        return self._result

    async def _worker(self, client: httpx.AsyncClient) -> None:
        """Worker coroutine that processes URLs from the queue."""
        while True:
            url, depth = await self._queue.get()

            if url == "__STOP__":
                self._queue.task_done()
                break

            if url in self._visited or depth > self.max_depth or len(self._visited) >= self.max_pages:
                self._queue.task_done()
                continue

            self._visited.add(url)

            try:
                async with self._semaphore:
                    await asyncio.sleep(self.rate_limit)  # Rate limiting
                    await self._process_page(client, url, depth)
            except Exception as e:
                self._result.errors.append(f"{url}: {e}")
            finally:
                self._queue.task_done()

    async def _process_page(self, client: httpx.AsyncClient, url: str, depth: int) -> None:
        """Fetch and analyze a single page."""
        try:
            resp = await client.get(url)
        except httpx.RequestError as e:
            log.debug("page_fetch_failed", url=url, error=str(e))
            return

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return

        html = resp.text
        if not html:
            return

        soup = BeautifulSoup(html, "lxml")

        # Extract links and queue them
        self._extract_links(soup, url, depth)

        # Extract forms
        self._extract_forms(soup, url)

        # Extract URL parameters from current URL
        self._extract_url_params(url)

        # Extract JS endpoints
        self._extract_js_endpoints(html, url)

        # Extract emails
        self._extract_emails(html)

        # Extract HTML comments
        self._extract_comments(soup)

        log.debug("page_crawled", url=url, depth=depth, queued=self._queue.qsize())

    def _extract_links(self, soup: BeautifulSoup, base_url: str, depth: int) -> None:
        """Extract and queue all internal links."""
        for tag in soup.find_all(["a", "area", "link"], href=True):
            href = tag.get("href", "").strip()
            if not href:
                continue

            abs_url = urljoin(base_url, href)
            abs_url = urldefrag(abs_url)[0]  # Remove fragment
            abs_url = self._normalize_url(abs_url)

            if not self._is_in_scope(abs_url):
                continue

            if abs_url not in self._visited and len(self._visited) < self.max_pages:
                try:
                    self._queue.put_nowait((abs_url, depth + 1))
                except asyncio.QueueFull:
                    pass

        # Also check iframe, frame, embed sources
        for tag in soup.find_all(["iframe", "frame", "embed"], src=True):
            src = urljoin(base_url, tag["src"])
            src = self._normalize_url(src)
            if self._is_in_scope(src) and src not in self._visited:
                try:
                    self._queue.put_nowait((src, depth + 1))
                except asyncio.QueueFull:
                    pass

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        """Extract all forms with their inputs."""
        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            if action:
                action_url = urljoin(page_url, action)
            else:
                action_url = page_url

            method = form.get("method", "GET").upper()

            inputs: list[dict[str, str]] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue

                input_type = inp.get("type", "text").lower()
                value = inp.get("value", "")
                placeholder = inp.get("placeholder", "")

                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                    "placeholder": placeholder,
                })

                # Track parameter names globally
                self._result.parameters.add(name)

            form_data = FormData(
                url=page_url,
                action=action_url,
                method=method,
                inputs=inputs,
            )
            self._result.forms.append(form_data)

            log.debug("form_discovered", page=page_url, action=action_url,
                      method=method, inputs=len(inputs))

    def _extract_url_params(self, url: str) -> None:
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name in params:
                self._result.parameters.add(name)

    def _extract_js_endpoints(self, html: str, base_url: str) -> None:
        """Extract potential API endpoints from JavaScript."""
        # Match common patterns in JavaScript
        patterns = [
            r'["\']/(api/[a-zA-Z0-9_/.-]+)["\']',
            r'["\']/(v[0-9]+/[a-zA-Z0-9_/.-]+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
            r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']*(?:api|endpoint|service)[^"\']*)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith("http"):
                    endpoint = match
                elif match.startswith("/"):
                    endpoint = urljoin(base_url, match)
                else:
                    endpoint = urljoin(base_url, "/" + match)

                if self._is_in_scope(endpoint):
                    self._result.js_endpoints.add(endpoint)

    def _extract_emails(self, html: str) -> None:
        """Extract email addresses from page content."""
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
        for email in emails:
            if not email.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.js')):
                self._result.emails.add(email)

    def _extract_comments(self, soup: BeautifulSoup) -> None:
        """Extract HTML comments that may contain sensitive info."""
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            text = comment.strip()
            if len(text) > 10:  # Skip trivial comments
                # Look for interesting content
                interesting_patterns = [
                    r'(?i)(password|secret|key|token|api|todo|fixme|hack|bug|admin|debug|config|database|credential)',
                ]
                for pattern in interesting_patterns:
                    if re.search(pattern, text):
                        self._result.comments.append(text[:500])  # Limit length
                        break

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within the crawl scope."""
        parsed = urlparse(url)

        # Must be same domain
        if parsed.netloc != self._base_domain:
            return False

        # Must be HTTP(S)
        if parsed.scheme not in ("http", "https"):
            return False

        # Check exclusion patterns
        for pattern in self.exclude_patterns:
            if pattern.search(url):
                return False

        return True

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for deduplication."""
        parsed = urlparse(url)
        # Remove fragment, normalize path
        path = parsed.path.rstrip("/") or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized


async def crawl_target(
    target_url: str,
    max_depth: int = 3,
    max_pages: int = 100,
    rate_limit: float = 0.1,
    verify_ssl: bool = True,
    http_client: httpx.AsyncClient | None = None,
) -> CrawlResult:
    """Convenience function to crawl a target.

    Args:
        target_url: Starting URL.
        max_depth: Maximum crawl depth (default 3).
        max_pages: Maximum pages to visit (default 100).
        rate_limit: Delay between requests in seconds.
        verify_ssl: Whether to verify SSL certificates.
        http_client: Optional shared HTTP client.

    Returns:
        CrawlResult with discovered pages, forms, and parameters.
    """
    crawler = WebCrawler(
        max_depth=max_depth,
        max_pages=max_pages,
        rate_limit=rate_limit,
        verify_ssl=verify_ssl,
    )
    return await crawler.crawl(target_url, http_client=http_client)
