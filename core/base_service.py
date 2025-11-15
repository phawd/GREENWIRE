"""Core service abstractions for the multithreaded issuer pipeline.

The goal of this module is to provide a lightweight, testable threading
infrastructure that all higher-level services (HSM, issuer, personalization,
merchant, transaction, telemetry) can inherit from.  It keeps the implementation
intentionally small so that hardware or emulator back-ends can focus on their
business logic while the orchestrator handles scheduling and persistence.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ServiceStatus(Enum):
    """Lifecycle state for a service managed by the orchestrator."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass(slots=True)
class ServiceMessage:
    """Envelope for messages exchanged between services."""

    topic: str
    payload: Dict[str, Any]
    source: str
    target: Optional[str] = None
    timestamp: float = field(default_factory=lambda: time.time())


@dataclass(slots=True)
class ServiceContext:
    """Shared utilities injected into each service instance."""

    name: str
    orchestrator: "ServiceOrchestrator"
    config: Dict[str, Any]
    logger: Any
    artifact_dir: str
    providers: Dict[str, Any]

    def send(self, message: ServiceMessage) -> None:
        """Proxy for context-aware publishing from inside a service."""

        self.orchestrator.publish(message)


class BaseService(threading.Thread):
    """Common service implementation with cooperative shutdown handling."""

    name: str = "service"
    subscriptions: tuple[str, ...] = ()

    def __init__(self, context: ServiceContext, poll_interval: float = 0.2) -> None:
        super().__init__(name=self.name, daemon=True)
        self._context = context
        self._poll_interval = poll_interval
        self._inbox: "queue.Queue[ServiceMessage]" = queue.Queue()
        self._status = ServiceStatus.STOPPED
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def on_start(self) -> None:  # pragma: no cover - meant for subclasses
        """Called synchronously when the service transitions to RUNNING."""

    def on_stop(self) -> None:  # pragma: no cover - meant for subclasses
        """Called during shutdown to allow subclasses to release resources."""

    def handle_message(self, message: ServiceMessage) -> None:  # pragma: no cover - override
        """Perform service-specific processing for an inbound message."""

    # ------------------------------------------------------------------
    # Public API used by the orchestrator
    # ------------------------------------------------------------------

    @property
    def status(self) -> ServiceStatus:
        return self._status

    @property
    def context(self) -> ServiceContext:
        return self._context

    def enqueue(self, message: ServiceMessage) -> None:
        self._inbox.put(message)

    def stop(self) -> None:
        self._status = ServiceStatus.STOPPING
        self._stop_event.set()
        self.join(timeout=5)
        if self._status != ServiceStatus.ERROR:
            self._status = ServiceStatus.STOPPED

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._status = ServiceStatus.STARTING
        try:
            self.on_start()
            self._status = ServiceStatus.RUNNING
        except Exception:  # pragma: no cover - logged by orchestrator
            self._context.logger.exception("%s failed during start", self.name)
            self._status = ServiceStatus.ERROR
            return

        while not self._stop_event.is_set():
            try:
                message = self._inbox.get(timeout=self._poll_interval)
            except queue.Empty:
                continue

            try:
                self.handle_message(message)
            except Exception:  # pragma: no cover - logged by orchestrator
                self._context.logger.exception("Unhandled exception in %s", self.name)
                self._status = ServiceStatus.ERROR
                self._stop_event.set()
                break

        try:
            self.on_stop()
        except Exception:  # pragma: no cover - shutdown best effort
            self._context.logger.exception("%s failed during stop", self.name)
        finally:
            if self._status != ServiceStatus.ERROR:
                self._status = ServiceStatus.STOPPED

    # ------------------------------------------------------------------
    # Helper methods for subclasses
    # ------------------------------------------------------------------

    def publish(self, topic: str, payload: Dict[str, Any], target: Optional[str] = None) -> None:
        """Send a message to another service via the orchestrator."""

        message = ServiceMessage(topic=topic, payload=payload, source=self.name, target=target)
        self._context.send(message)


# Late import to avoid circular dependency when typing ServiceContext
from core.service_orchestrator import ServiceOrchestrator  # noqa  # isort: skip