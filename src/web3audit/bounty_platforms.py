from __future__ import annotations

import time
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any, Optional

import requests
from requests import Response
from requests.exceptions import RequestException
try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None


class PlatformAPIError(RuntimeError):
    pass


@dataclass
class RetryConfig:
    retries: int = 3
    base_delay: float = 1.0


def _retry_request(func, config: RetryConfig) -> Response:
    last_exc: Optional[Exception] = None
    for attempt in range(1, config.retries + 1):
        try:
            response = func()
            if response.status_code == 429 and attempt < config.retries:
                time.sleep(min(60.0, config.base_delay * (2 ** (attempt - 1))))
                continue
            response.raise_for_status()
            return response
        except RequestException as exc:
            last_exc = exc
            if attempt >= config.retries:
                break
            time.sleep(min(60.0, config.base_delay * (2 ** (attempt - 1))))
    raise PlatformAPIError(f"Platform request failed after retries: {last_exc}")


def report_fingerprint(contract_address: str, title: str) -> str:
    normalized = f"{contract_address.lower()}::{title.strip().lower()}"
    return sha256(normalized.encode("utf-8")).hexdigest()


class ImmunefiClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def fetch_active_bounties(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/api/bounties"
        response = _retry_request(
            lambda: requests.get(url, headers=self._headers(), timeout=self.timeout),
            RetryConfig(),
        )
        payload = response.json()
        items = payload.get("results") if isinstance(payload, dict) else payload
        return [item for item in (items or []) if item.get("status", "active") == "active"]

    def fetch_scope(self, program_id: str) -> list[dict[str, Any]]:
        url = f"{self.base_url}/api/bounties/{program_id}"
        response = _retry_request(
            lambda: requests.get(url, headers=self._headers(), timeout=self.timeout),
            RetryConfig(),
        )
        payload = response.json()
        scope = payload.get("scope", []) if isinstance(payload, dict) else []
        return scope if isinstance(scope, list) else []

    def check_existing_reports(self, contract_address: str) -> bool:
        url = f"{self.base_url}/api/reports/search"
        response = _retry_request(
            lambda: requests.get(
                url,
                params={"contract": contract_address},
                headers=self._headers(),
                timeout=self.timeout,
            ),
            RetryConfig(),
        )
        payload = response.json()
        matches = payload.get("results", []) if isinstance(payload, dict) else []
        return bool(matches)


class HackenProofClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"
        return headers

    def fetch_active_bounties(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/api/programs"
        response = _retry_request(
            lambda: requests.get(url, headers=self._headers(), timeout=self.timeout),
            RetryConfig(),
        )
        payload = response.json()
        programs = payload.get("results") if isinstance(payload, dict) else payload
        return [item for item in (programs or []) if item.get("status", "active") == "active"]

    def fetch_scope(self, program_slug: str) -> list[dict[str, Any]]:
        url = f"{self.base_url}/api/programs/{program_slug}"
        response = _retry_request(
            lambda: requests.get(url, headers=self._headers(), timeout=self.timeout),
            RetryConfig(),
        )
        payload = response.json()
        scope = payload.get("scope", []) if isinstance(payload, dict) else []
        return scope if isinstance(scope, list) else []

    def check_existing_reports(self, contract_address: str) -> bool:
        url = f"{self.base_url}/api/reports"
        response = _retry_request(
            lambda: requests.get(
                url,
                params={"contract": contract_address},
                headers=self._headers(),
                timeout=self.timeout,
            ),
            RetryConfig(),
        )
        payload = response.json()
        reports = payload.get("results", []) if isinstance(payload, dict) else []
        return bool(reports)


class CantinaClient:
    def __init__(self, base_url: str, timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def fetch_contests(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/competitions"
        response = _retry_request(
            lambda: requests.get(url, timeout=self.timeout),
            RetryConfig(),
        )
        contests: list[dict[str, Any]] = []
        if BeautifulSoup is not None:
            soup = BeautifulSoup(response.text, "html.parser")
            for anchor in soup.select("a[href*='/competitions/']"):
                href = anchor.get("href", "")
                title = " ".join(anchor.get_text(strip=True).split())
                if not href or not title:
                    continue
                contests.append({"title": title, "url": f"{self.base_url}{href}" if href.startswith("/") else href})
        else:
            hrefs = re.findall(r'href=[\'"]([^\'"]+/competitions/[^\'"]+)[\'"]', response.text, re.IGNORECASE)
            for href in hrefs:
                normalized = f"{self.base_url}{href}" if href.startswith("/") else href
                contests.append({"title": "contest", "url": normalized})
        unique: dict[str, dict[str, Any]] = {}
        for contest in contests:
            unique[contest["url"]] = contest
        return list(unique.values())

    def check_existing_reports(self, contract_address: str) -> bool:
        query = contract_address.lower()
        for contest in self.fetch_contests():
            response = _retry_request(
                lambda: requests.get(contest["url"], timeout=self.timeout),
                RetryConfig(retries=2, base_delay=0.5),
            )
            if query in response.text.lower():
                return True
        return False


def check_duplicate_across_platforms(
    contract_address: str,
    immunefi_client: Optional[ImmunefiClient] = None,
    hackenproof_client: Optional[HackenProofClient] = None,
    cantina_client: Optional[CantinaClient] = None,
) -> tuple[bool, str]:
    checks: list[tuple[str, Optional[bool]]] = []

    if immunefi_client is not None:
        try:
            checks.append(("immunefi", immunefi_client.check_existing_reports(contract_address)))
        except PlatformAPIError:
            checks.append(("immunefi", None))

    if hackenproof_client is not None:
        try:
            checks.append(("hackenproof", hackenproof_client.check_existing_reports(contract_address)))
        except PlatformAPIError:
            checks.append(("hackenproof", None))

    if cantina_client is not None:
        try:
            checks.append(("cantina", cantina_client.check_existing_reports(contract_address)))
        except PlatformAPIError:
            checks.append(("cantina", None))

    positives = [name for name, result in checks if result is True]
    if positives:
        return True, f"Potential duplicate report signal on: {', '.join(positives)}"

    unknowns = [name for name, result in checks if result is None]
    if unknowns:
        return False, f"Duplicate check incomplete due to API errors: {', '.join(unknowns)}"

    return False, "No duplicate report signal detected on configured platforms"
