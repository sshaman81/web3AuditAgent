from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin

import requests

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

COMPARISON_KEYWORDS = (
    "comparison",
    "compare",
    "equality",
    "inequality",
    "rounding",
    "precision",
    "truncation",
    "decimal",
)


def _extract_markdown_links(text: str, base_url: str) -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    for title, href in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text):
        normalized = urljoin(base_url, href.strip())
        links.append((title.strip(), normalized))
    return links


def _extract_html_links(text: str, base_url: str) -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    if BeautifulSoup is not None:
        soup = BeautifulSoup(text, "html.parser")
        for anchor in soup.select("a[href]"):
            href = anchor.get("href", "").strip()
            title = " ".join(anchor.get_text(" ", strip=True).split())
            if not href or not title:
                continue
            links.append((title, urljoin(base_url, href)))
        return links

    for href in re.findall(r'href=[\'"]([^\'"]+)[\'"]', text, re.IGNORECASE):
        links.append(("reference", urljoin(base_url, href.strip())))
    return links


def _is_comparison_related(*parts: str) -> bool:
    merged = " ".join(part.lower() for part in parts if part)
    return any(keyword in merged for keyword in COMPARISON_KEYWORDS)


def _download_text(url: str, timeout_seconds: int) -> str:
    response = requests.get(url, timeout=timeout_seconds)
    response.raise_for_status()
    return response.text


def fetch_comparison_bug_references(
    index_url: str,
    timeout_seconds: int = 10,
    max_refs: int = 5,
) -> list[dict[str, str]]:
    # Crawl only a few pages to keep latency bounded.
    to_visit = [index_url]
    visited: set[str] = set()
    seen_urls: set[str] = set()
    results: list[dict[str, str]] = []

    while to_visit and len(visited) < 4 and len(results) < max_refs:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            text = _download_text(url, timeout_seconds=timeout_seconds)
        except Exception:
            continue

        links = _extract_markdown_links(text, base_url=url)
        links.extend(_extract_html_links(text, base_url=url))

        for title, link in links:
            title_clean = " ".join(title.split())
            if not title_clean or not link.startswith(("http://", "https://")):
                continue
            if link in seen_urls:
                continue
            seen_urls.add(link)

            if _is_comparison_related(title_clean, link):
                results.append({"title": title_clean, "url": link})
                if len(results) >= max_refs:
                    break

            # Follow the vulnerability index as a second hop to discover note links.
            if "vulnerability-patterns" in link and link not in visited and link not in to_visit:
                to_visit.append(link)

    return results[:max_refs]


def render_comparison_bug_context(references: list[dict[str, str]]) -> str:
    if not references:
        return ""
    lines = ["Historical comparison/precision bug references (EVM Research):"]
    for item in references:
        title = item.get("title", "").strip()
        url = item.get("url", "").strip()
        if title and url:
            lines.append(f"- {title}: {url}")
    return "\n".join(lines)


def load_comparison_bug_context(
    index_url: str,
    timeout_seconds: int = 10,
    max_refs: int = 5,
) -> str:
    refs = fetch_comparison_bug_references(
        index_url=index_url,
        timeout_seconds=timeout_seconds,
        max_refs=max_refs,
    )
    return render_comparison_bug_context(refs)
