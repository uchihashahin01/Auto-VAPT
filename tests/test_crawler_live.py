"""Standalone crawler test — verifies all extraction features."""

import asyncio
import json
import sys
sys.path.insert(0, "/home/uchiha/Desktop/Auto-VAPT")

from auto_vapt.crawler import WebCrawler, crawl_target


async def test_crawler():
    print("=" * 70)
    print("  Auto-VAPT Web Crawler — Feature Test")
    print("=" * 70)

    target = "http://testphp.vulnweb.com"
    print(f"\n🎯 Target: {target}")
    print(f"   Max Depth: 3  |  Max Pages: 50\n")

    crawler = WebCrawler(max_depth=3, max_pages=50, rate_limit=0.05)
    result = await crawler.crawl(target)

    # 1. Page Discovery
    print("─" * 70)
    print(f"📄 PAGES DISCOVERED: {result.total_pages}")
    print("─" * 70)
    for url in sorted(result.discovered_urls)[:20]:
        print(f"   • {url}")
    if result.total_pages > 20:
        print(f"   ... and {result.total_pages - 20} more")

    # 2. Forms
    print(f"\n{'─' * 70}")
    print(f"📋 FORMS FOUND: {len(result.forms)}")
    print("─" * 70)
    for i, form in enumerate(result.forms[:15]):
        print(f"   Form #{i+1}:")
        print(f"     Page:   {form.url}")
        print(f"     Action: {form.action}")
        print(f"     Method: {form.method}")
        print(f"     Inputs: {', '.join(form.parameters) or 'none'}")
        print()

    # 3. Parameters
    print(f"{'─' * 70}")
    print(f"🔑 UNIQUE PARAMETERS: {len(result.parameters)}")
    print("─" * 70)
    for param in sorted(result.parameters):
        print(f"   • {param}")

    # 4. JS Endpoints
    print(f"\n{'─' * 70}")
    print(f"⚡ JS ENDPOINTS: {len(result.js_endpoints)}")
    print("─" * 70)
    for ep in sorted(result.js_endpoints)[:10]:
        print(f"   • {ep}")

    # 5. Emails
    print(f"\n{'─' * 70}")
    print(f"📧 EMAILS FOUND: {len(result.emails)}")
    print("─" * 70)
    for email in sorted(result.emails):
        print(f"   • {email}")

    # 6. HTML Comments
    print(f"\n{'─' * 70}")
    print(f"💬 INTERESTING COMMENTS: {len(result.comments)}")
    print("─" * 70)
    for comment in result.comments[:5]:
        print(f"   • {comment[:120]}...")

    # 7. Errors
    if result.errors:
        print(f"\n{'─' * 70}")
        print(f"⚠️  ERRORS: {len(result.errors)}")
        print("─" * 70)
        for err in result.errors[:5]:
            print(f"   • {err[:120]}")

    # Summary
    print(f"\n{'=' * 70}")
    print("  SUMMARY")
    print("=" * 70)
    summary = result.summary()
    for key, value in summary.items():
        print(f"   {key:.<25} {value}")

    # Validation checks
    print(f"\n{'=' * 70}")
    print("  VALIDATION")
    print("=" * 70)
    checks = [
        ("Pages discovered > 5", result.total_pages > 5),
        ("Forms found > 0", len(result.forms) > 0),
        ("Parameters extracted > 0", len(result.parameters) > 0),
        ("No critical errors", len(result.errors) < result.total_pages),
        ("Form actions are absolute URLs", all(f.action.startswith("http") for f in result.forms[:5] if f.action)),
        ("All URLs are same-domain", all("testphp.vulnweb.com" in u for u in result.discovered_urls)),
    ]

    all_pass = True
    for name, passed in checks:
        icon = "✅" if passed else "❌"
        print(f"   {icon} {name}")
        if not passed:
            all_pass = False

    print(f"\n   {'🎉 ALL CHECKS PASSED!' if all_pass else '⚠️  SOME CHECKS FAILED'}")
    return all_pass


if __name__ == "__main__":
    success = asyncio.run(test_crawler())
    sys.exit(0 if success else 1)
