from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from pydantic import ValidationError

from logger import get_logger

logger = get_logger(__name__)

ErrorType = str


def classify_error(exception: Exception) -> ErrorType:
    message = str(exception).lower()
    if "rate limit" in message or "too many requests" in message or "quota" in message:
        return "rate_limit"
    if "context" in message and ("length" in message or "overflow" in message or "token" in message):
        return "context_overflow"
    if "forge" in message or "foundry" in message or isinstance(exception, RuntimeError):
        return "tool_error"
    if "model" in message or "anthropic" in message or isinstance(exception, ValidationError):
        return "model_error"
    return "unknown"


@dataclass
class CircuitBreaker:
    failure_threshold: int
    recovery_seconds: int
    failure_count: int = 0
    opened_at: Optional[float] = None

    def allow_request(self) -> bool:
        if self.opened_at is None:
            return True
        elapsed = time.monotonic() - self.opened_at
        return elapsed >= self.recovery_seconds

    def record_success(self) -> None:
        self.failure_count = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.opened_at = time.monotonic()


@dataclass
class ErrorHandlingMiddleware:
    max_attempts: int
    breaker_failure_threshold: int
    breaker_recovery_seconds: int
    max_backoff_seconds: int = 60
    breakers: dict[str, CircuitBreaker] = field(default_factory=dict)

    def _get_breaker(self, node_name: str) -> CircuitBreaker:
        if node_name not in self.breakers:
            self.breakers[node_name] = CircuitBreaker(
                failure_threshold=self.breaker_failure_threshold,
                recovery_seconds=self.breaker_recovery_seconds,
            )
        return self.breakers[node_name]

    def run_with_retries(
        self,
        node_name: str,
        action: Callable[[], dict[str, Any]],
        error_log: dict[str, list[str]],
        on_context_overflow: Optional[Callable[[Exception], dict[str, Any]]] = None,
        on_tool_error: Optional[Callable[[Exception], dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        updates: dict[str, Any] = {}
        breaker = self._get_breaker(node_name)

        if not breaker.allow_request():
            raise RuntimeError(f"Circuit breaker open for node '{node_name}'")

        for attempt in range(1, self.max_attempts + 1):
            try:
                result = action()
                breaker.record_success()
                merged = {"node_errors": error_log}
                merged.update(updates)
                merged.update(result)
                return merged
            except Exception as exc:
                err_type = classify_error(exc)
                entry = f"{node_name} attempt {attempt} [{err_type}]: {type(exc).__name__} - {exc}"
                error_log.setdefault(node_name, []).append(entry)
                logger.error(
                    "Node execution failed",
                    extra={
                        "context": {
                            "node": node_name,
                            "attempt": attempt,
                            "error_type": err_type,
                            "error": str(exc),
                        }
                    },
                )

                if err_type in {"rate_limit", "model_error", "unknown"}:
                    breaker.record_failure()

                if err_type == "rate_limit" and attempt < self.max_attempts:
                    delay = min(self.max_backoff_seconds, 2 ** attempt)
                    time.sleep(delay)
                    continue

                if err_type == "context_overflow" and on_context_overflow and attempt < self.max_attempts:
                    overflow_updates = on_context_overflow(exc)
                    updates.update(overflow_updates)
                    continue

                if err_type == "tool_error" and on_tool_error:
                    tool_updates = on_tool_error(exc)
                    updates.update(tool_updates)
                    updates["node_errors"] = error_log
                    return updates

                if attempt >= self.max_attempts:
                    raise RuntimeError(
                        f"Node '{node_name}' exceeded retry cap ({self.max_attempts})"
                    ) from exc

        raise RuntimeError(f"Node '{node_name}' failed unexpectedly without a terminal error")
