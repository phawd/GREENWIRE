"""Service orchestrator coordinating the multithreaded issuer pipeline."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Optional

from core.base_service import BaseService, ServiceContext, ServiceMessage, ServiceStatus
from core.logging_system import get_logger


class ServiceOrchestrator:
    """Register, start, and route messages between services."""

    def __init__(
        self,
        *,
        artifact_dir: Path | str = Path("artifacts"),
        database_path: Path | str = Path("artifacts/orchestrator.db"),
        config: Optional[Dict[str, object]] = None,
        providers: Optional[Dict[str, object]] = None,
    ) -> None:
        self._artifact_dir = Path(artifact_dir)
        self._database_path = Path(database_path)
        self._config = config or {}
        self._providers = providers or {}
        self._services: Dict[str, BaseService] = {}
        self._subscriptions: Dict[str, set[str]] = defaultdict(set)
        self._lock = threading.RLock()
        self._logger = get_logger("service_orchestrator")
        self._mode = "emulator"

        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_database()

    # ------------------------------------------------------------------
    # Registration and lifecycle
    # ------------------------------------------------------------------

    def register(self, service_cls: type[BaseService], *, name: Optional[str] = None, **kwargs) -> BaseService:
        name = name or service_cls.name
        if not name:
            raise ValueError("Services must define a name")
        with self._lock:
            if name in self._services:
                raise ValueError(f"Service '{name}' already registered")

            context = ServiceContext(
                name=name,
                orchestrator=self,
                config={**self._config, **kwargs.pop("config", {})},
                logger=get_logger(name),
                artifact_dir=str(self._artifact_dir),
                providers={**self._providers, **kwargs.pop("providers", {})},
            )

            instance = service_cls(context=context, **kwargs)
            self._services[name] = instance
            for topic in instance.subscriptions:
                self._subscriptions[topic].add(name)

        return instance

    def start_all(self) -> None:
        with self._lock:
            for service in self._services.values():
                if service.status is ServiceStatus.RUNNING:
                    continue
                service.start()

    def stop_all(self) -> None:
        with self._lock:
            for service in self._services.values():
                if service.status in (ServiceStatus.STOPPED, ServiceStatus.STOPPING):
                    continue
                service.stop()

    def get_status(self) -> Dict[str, str]:
        with self._lock:
            status = {name: service.status.value for name, service in self._services.items()}
            status["mode"] = self._mode
            return status

    def switch_mode(self, mode: str) -> str:
        mode = mode.lower()
        with self._lock:
            if mode == self._mode:
                return self._mode
            self._mode = mode
            self._logger.info("Service orchestrator switched to %s mode", mode)
        return self._mode

    @property
    def mode(self) -> str:
        return self._mode

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    def publish(self, message: ServiceMessage) -> None:
        """Persist and forward a message to subscribed services."""

        self._persist_message(message)
        targets = self._resolve_targets(message)
        if not targets:
            self._logger.warning("Message %s had no subscribers", message.topic)
            return

        for target in targets:
            service = self._services.get(target)
            if not service:
                continue
            service.enqueue(message)

    def dispatch(self, topic: str, payload: Dict[str, object], *, source: str = "cli", target: str | None = None) -> None:
        message = ServiceMessage(topic=topic, payload=dict(payload), source=source, target=target)
        self.publish(message)

    def _resolve_targets(self, message: ServiceMessage) -> Iterable[str]:
        if message.target:
            return (message.target,) if message.target in self._services else ()
        return tuple(self._subscriptions.get(message.topic, ()))

    # ------------------------------------------------------------------
    # Persistence layer
    # ------------------------------------------------------------------

    def _ensure_database(self) -> None:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._database_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created REAL NOT NULL,
                    topic TEXT NOT NULL,
                    source TEXT NOT NULL,
                    target TEXT,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _persist_message(self, message: ServiceMessage) -> None:
        conn = sqlite3.connect(self._database_path)
        try:
            try:
                serialised = json.dumps(message.payload)
            except TypeError:
                serialised = repr(message.payload)
            conn.execute(
                "INSERT INTO messages (created, topic, source, target, payload) VALUES (?, ?, ?, ?, ?)",
                (message.timestamp, message.topic, message.source, message.target, serialised),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Convenience helpers for CLI
    # ------------------------------------------------------------------

    def wait_for_completion(self, topic: str, timeout: float = 10.0) -> Optional[ServiceMessage]:
        """Block until a message with the given topic is recorded in the database."""

        deadline = time.time() + timeout
        last_id = 0
        while time.time() < deadline:
            conn = sqlite3.connect(self._database_path)
            try:
                row = conn.execute(
                    "SELECT id, created, topic, source, target, payload FROM messages WHERE topic = ? AND id > ? ORDER BY id DESC LIMIT 1",
                    (topic, last_id),
                ).fetchone()
            finally:
                conn.close()

            if not row:
                time.sleep(0.2)
                continue

            last_id = row[0]
            payload = row[5]
            try:
                payload_data = json.loads(payload)
            except (TypeError, json.JSONDecodeError):
                payload_data = {"raw": payload}
            return ServiceMessage(
                topic=row[2],
                payload=payload_data,
                source=row[3],
                target=row[4],
                timestamp=row[1],
            )
        return None


__all__ = ["ServiceOrchestrator"]
