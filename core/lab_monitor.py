"""
GREENWIRE Lab Monitor
=====================
Centralised status and log registry for all lab components.

Every component in the lab (ATM emulator, POS terminal, HCE emulator, HSM,
merchant profiles, Android bridge) calls ``get_monitor()`` to obtain the
singleton ``LabMonitor`` and then:

  1. **Registers** itself with a component ID and type.
  2. **Posts events** (log lines, transaction records, status changes).
  3. Optionally **updates its status** (IDLE / ACTIVE / ERROR / OFFLINE).

The monitor collects everything in memory (thread-safe deques) and also
appends every event to a JSON-lines log file for post-session analysis.

The companion ``lab_ui.py`` reads from this monitor to drive the live
Rich terminal dashboard.

DESIGN PRINCIPLES
─────────────────
• **Zero coupling** — components import the monitor; the monitor never
  imports any component.  Adding a new component never touches this file.

• **Thread-safe** — all writes go through a single ``threading.Lock``.
  The dashboard can read snapshots freely; it only needs the lock briefly.

• **Low overhead** — events are stored in ``collections.deque`` with a
  configurable ``maxlen`` so memory stays bounded even in long lab sessions.

• **Persistent** — every event is appended to ``logs/lab_session.jsonl``
  in JSON-lines format so you can grep/jq the file after the session ends.

QUICK START
───────────
    # In any component:
    from core.lab_monitor import get_monitor, ComponentType, EventLevel

    mon = get_monitor()
    mon.register("atm-001", ComponentType.ATM, "Main Branch ATM")
    mon.event("atm-001", EventLevel.INFO, "Card inserted", pan_masked="4111xxxxxxxx1111")
    mon.transaction("atm-001", amount=5000, currency="GBP", outcome="APPROVED",
                    scheme="visa", approval_code="AUTH123")
    mon.set_status("atm-001", "ACTIVE")

    # In the dashboard / CLI:
    from core.lab_monitor import get_monitor
    mon = get_monitor()
    snapshot = mon.snapshot()    # returns LabSnapshot dataclass
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_EVENTS_PER_COMPONENT = 500   # Ring-buffer depth per component
MAX_GLOBAL_EVENTS        = 2000  # Global event stream depth
LOG_DIR                  = Path("logs")
SESSION_LOG_FILE         = LOG_DIR / "lab_session.jsonl"


# ── Enumerations ──────────────────────────────────────────────────────────────

class ComponentType(str, Enum):
    """
    Category of lab component.

    Used by the dashboard to group panels and choose status-indicator colours:
      ATM        → blue panel   (banking hardware)
      POS        → green panel  (merchant hardware)
      HCE        → cyan panel   (software card / Android)
      HSM        → magenta panel (key management)
      ANDROID    → yellow panel (ADB-connected device)
      TSP        → white panel  (Visa VTS / MC MDES sandbox)
      CARD       → red panel    (predator card scenario)
      GENERIC    → grey panel   (anything else)
    """
    ATM     = "ATM"
    POS     = "POS"
    HCE     = "HCE"
    HSM     = "HSM"
    ANDROID = "ANDROID"
    TSP     = "TSP"
    CARD    = "CARD"
    GENERIC = "GENERIC"


class EventLevel(str, Enum):
    """
    Severity level for a lab event — mirrors Python logging levels but
    lives in the monitor so components don't need to import logging directly.
    """
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARNING  = "WARNING"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"


class ComponentStatus(str, Enum):
    """
    Operational status of a registered component.

    IDLE     — registered but not currently processing a transaction
    ACTIVE   — currently processing (card inserted / transaction in flight)
    ERROR    — last operation failed; see last event for details
    OFFLINE  — component has been shut down or is unreachable
    """
    IDLE    = "IDLE"
    ACTIVE  = "ACTIVE"
    ERROR   = "ERROR"
    OFFLINE = "OFFLINE"


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class LabEvent:
    """
    A single log event from any component.

    All fields are primitives so the event can be serialised to JSON
    without any special encoder.
    """
    ts: float                        # Unix timestamp (time.time())
    component_id: str                # e.g. "atm-001", "pos-tesco-lane3"
    component_type: str              # ComponentType value string
    level: str                       # EventLevel value string
    message: str                     # Human-readable log message
    extra: Dict[str, Any]            # Any additional structured fields

    @property
    def iso_ts(self) -> str:
        """ISO-8601 timestamp string for display."""
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).strftime(
            "%H:%M:%S.%f"
        )[:-3]   # HH:MM:SS.mmm

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["iso_ts"] = self.iso_ts
        return d


@dataclass
class TransactionRecord:
    """
    Immutable record of a completed (or failed) transaction.

    Stored separately from events so the dashboard can show a clean
    transaction table alongside the raw log stream.
    """
    ts: float
    component_id: str
    amount_minor: int        # amount in smallest currency unit (pence / cents)
    currency: str            # ISO 4217 alpha-3 e.g. "GBP", "USD"
    outcome: str             # "APPROVED", "DECLINED", "ERROR", "REFERRAL"
    scheme: str              # "visa", "mastercard", etc.
    pan_masked: str          # e.g. "4111 xxxx xxxx 1111"
    approval_code: str       # 6-char alpha-numeric, or "" on decline
    auth_response_code: str  # ISO 8583 DE39, e.g. "00", "05", "51"
    scenario_id: str         # predator scenario ID if applicable, else ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def amount_display(self) -> str:
        """Format amount as decimal string (e.g. '23.50')."""
        return f"{self.amount_minor / 100:.2f}"

    @property
    def iso_ts(self) -> str:
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).strftime(
            "%H:%M:%S"
        )


@dataclass
class ComponentRecord:
    """Everything the monitor knows about one registered component."""
    component_id: str
    component_type: ComponentType
    label: str                       # Human-readable name
    status: ComponentStatus = ComponentStatus.IDLE
    registered_at: float = field(default_factory=time.time)
    last_event_at: float = 0.0
    last_event_msg: str = ""
    txn_count: int = 0
    txn_approved: int = 0
    txn_declined: int = 0
    txn_errors: int = 0
    events: Deque[LabEvent] = field(
        default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_COMPONENT)
    )
    transactions: Deque[TransactionRecord] = field(
        default_factory=lambda: deque(maxlen=100)
    )


@dataclass
class LabSnapshot:
    """
    A point-in-time snapshot of the entire lab state.

    Produced by ``LabMonitor.snapshot()`` — safe to read without holding
    the monitor lock since it contains copies, not live references.
    """
    snapshot_ts: float
    components: Dict[str, ComponentRecord]
    recent_events: List[LabEvent]           # global stream, newest last
    recent_transactions: List[TransactionRecord]
    total_transactions: int
    total_approved: int
    total_declined: int
    total_errors: int


# ── Core monitor class ────────────────────────────────────────────────────────

class LabMonitor:
    """
    Singleton monitor for all GREENWIRE lab components.

    Thread-safe.  Use ``get_monitor()`` to obtain the singleton rather
    than instantiating directly.
    """

    def __init__(self, log_file: Optional[Path] = None):
        self._lock = threading.Lock()
        self._components: Dict[str, ComponentRecord] = {}
        self._global_events: Deque[LabEvent] = deque(maxlen=MAX_GLOBAL_EVENTS)
        self._global_transactions: Deque[TransactionRecord] = deque(maxlen=500)

        # counters
        self._total_txns = 0
        self._total_approved = 0
        self._total_declined = 0
        self._total_errors = 0

        # persistent log
        self._log_file: Optional[Path] = log_file or SESSION_LOG_FILE
        self._log_fh = None
        self._open_log_file()

        logger.debug("LabMonitor initialised — log: %s", self._log_file)

    # ── Component registration ─────────────────────────────────────────────

    def register(
        self,
        component_id: str,
        component_type: ComponentType,
        label: str = "",
    ) -> None:
        """
        Register a component so the monitor knows about it.

        Call this once during component ``__init__``.  Re-registering an
        existing ID updates the label and resets counters.

        Args:
            component_id:   Unique string ID, e.g. "atm-001", "pos-tesco-lane3"
            component_type: ComponentType enum value
            label:          Human-readable name shown in the dashboard
        """
        with self._lock:
            self._components[component_id] = ComponentRecord(
                component_id=component_id,
                component_type=component_type,
                label=label or component_id,
            )
        logger.debug("Registered component: %s (%s)", component_id, component_type.value)

    def unregister(self, component_id: str) -> None:
        """Remove a component from the registry (call on shutdown)."""
        with self._lock:
            self._components.pop(component_id, None)

    def set_status(self, component_id: str, status: ComponentStatus | str) -> None:
        """
        Update the operational status of a component.

        Args:
            component_id: ID previously passed to ``register()``.
            status:       ComponentStatus enum or its string value.
        """
        if isinstance(status, str):
            status = ComponentStatus(status)
        with self._lock:
            if component_id in self._components:
                self._components[component_id].status = status

    # ── Event posting ──────────────────────────────────────────────────────

    def event(
        self,
        component_id: str,
        level: EventLevel | str,
        message: str,
        **extra: Any,
    ) -> None:
        """
        Post a log event from a component.

        This is the primary method components call to log anything — card
        insertions, APDU exchanges, PIN attempts, errors, etc.

        Args:
            component_id: Registered component ID.
            level:        EventLevel (or string "INFO", "ERROR", etc.)
            message:      Human-readable description of the event.
            **extra:      Any additional structured fields to include
                          (e.g. pan_masked="4111xxxx", sw="9000", atc=42)

        Example:
            mon.event("pos-001", EventLevel.INFO, "Card tapped",
                      pan_masked="4895xxxx0001", scheme="visa", amount_minor=2350)
        """
        if isinstance(level, str):
            level = EventLevel(level)

        # Auto-register unknown components rather than silently dropping events
        with self._lock:
            if component_id not in self._components:
                self._components[component_id] = ComponentRecord(
                    component_id=component_id,
                    component_type=ComponentType.GENERIC,
                    label=component_id,
                )

            comp_type = self._components[component_id].component_type.value
            ev = LabEvent(
                ts=time.time(),
                component_id=component_id,
                component_type=comp_type,
                level=level.value,
                message=message,
                extra=extra,
            )
            self._components[component_id].events.append(ev)
            self._components[component_id].last_event_at = ev.ts
            self._components[component_id].last_event_msg = message
            self._global_events.append(ev)

        # Write to file outside the lock to avoid blocking readers
        self._write_log(ev)

        # Mirror to Python logging so existing log infrastructure sees it too
        _LOG_LEVEL_MAP = {
            "DEBUG": logging.DEBUG, "INFO": logging.INFO,
            "WARNING": logging.WARNING, "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        logging.getLogger(f"lab.{component_id}").log(
            _LOG_LEVEL_MAP.get(level.value, logging.INFO),
            "[%s] %s", component_id, message,
        )

    def transaction(
        self,
        component_id: str,
        amount_minor: int,
        currency: str,
        outcome: str,
        scheme: str = "unknown",
        pan_masked: str = "",
        approval_code: str = "",
        auth_response_code: str = "00",
        scenario_id: str = "",
        **extra: Any,
    ) -> TransactionRecord:
        """
        Record a completed transaction and update component counters.

        Args:
            component_id:       Registered component ID.
            amount_minor:       Transaction amount in smallest currency unit.
            currency:           ISO 4217 alpha-3 code ("GBP", "USD", …).
            outcome:            "APPROVED", "DECLINED", "ERROR", or "REFERRAL".
            scheme:             Payment scheme ("visa", "mastercard", …).
            pan_masked:         PAN with middle digits replaced by 'x'.
            approval_code:      6-char auth code (empty on decline).
            auth_response_code: ISO 8583 DE39 response code.
            scenario_id:        Predator scenario ID if applicable.
            **extra:            Any additional fields (atc, arqc, etc.)

        Returns:
            The TransactionRecord that was created.
        """
        rec = TransactionRecord(
            ts=time.time(),
            component_id=component_id,
            amount_minor=amount_minor,
            currency=currency,
            outcome=outcome.upper(),
            scheme=scheme,
            pan_masked=pan_masked,
            approval_code=approval_code,
            auth_response_code=auth_response_code,
            scenario_id=scenario_id,
            extra=extra,
        )
        with self._lock:
            if component_id in self._components:
                c = self._components[component_id]
                c.txn_count += 1
                if outcome.upper() == "APPROVED":
                    c.txn_approved += 1
                elif outcome.upper() == "DECLINED":
                    c.txn_declined += 1
                else:
                    c.txn_errors += 1
                c.transactions.append(rec)

            self._global_transactions.append(rec)
            self._total_txns += 1
            if outcome.upper() == "APPROVED":
                self._total_approved += 1
            elif outcome.upper() == "DECLINED":
                self._total_declined += 1
            else:
                self._total_errors += 1

        # Log the transaction as an event too
        self.event(
            component_id, EventLevel.INFO,
            f"TXN {outcome.upper()} {amount_minor/100:.2f} {currency} "
            f"[{scheme.upper()}] auth={approval_code or 'N/A'}",
            amount_minor=amount_minor, currency=currency, outcome=outcome,
            scheme=scheme, pan_masked=pan_masked,
            approval_code=approval_code, scenario_id=scenario_id,
        )
        self._write_log(rec)
        return rec

    # ── Snapshot / query ──────────────────────────────────────────────────

    def snapshot(self) -> LabSnapshot:
        """
        Return a point-in-time snapshot of the entire lab state.

        The snapshot contains shallow copies of all component records and
        list copies of the event / transaction deques.  It is safe to read
        after this call returns without holding the lock.
        """
        with self._lock:
            return LabSnapshot(
                snapshot_ts=time.time(),
                components=dict(self._components),  # component refs are shared but deques are live
                recent_events=list(self._global_events)[-100:],
                recent_transactions=list(self._global_transactions)[-50:],
                total_transactions=self._total_txns,
                total_approved=self._total_approved,
                total_declined=self._total_declined,
                total_errors=self._total_errors,
            )

    def component_events(
        self, component_id: str, last_n: int = 50
    ) -> List[LabEvent]:
        """Return the most recent N events for a specific component."""
        with self._lock:
            comp = self._components.get(component_id)
            if comp is None:
                return []
            return list(comp.events)[-last_n:]

    def component_transactions(
        self, component_id: str, last_n: int = 20
    ) -> List[TransactionRecord]:
        """Return the most recent N transactions for a specific component."""
        with self._lock:
            comp = self._components.get(component_id)
            if comp is None:
                return []
            return list(comp.transactions)[-last_n:]

    def registered_ids(self) -> List[str]:
        """Return a sorted list of all registered component IDs."""
        with self._lock:
            return sorted(self._components.keys())

    # ── Persistent log ────────────────────────────────────────────────────

    def _open_log_file(self) -> None:
        """Open (or create) the JSON-lines session log file."""
        if self._log_file is None:
            return
        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            self._log_fh = self._log_file.open("a", encoding="utf-8")
            logger.debug("Session log: %s", self._log_file)
        except OSError as e:
            logger.warning("Cannot open session log %s: %s", self._log_file, e)
            self._log_fh = None

    def _write_log(self, record: Any) -> None:
        """Append one record to the JSON-lines log file."""
        if self._log_fh is None:
            return
        try:
            if hasattr(record, "to_dict"):
                line = json.dumps(record.to_dict())
            elif hasattr(record, "__dataclass_fields__"):
                line = json.dumps(asdict(record))
            else:
                line = json.dumps(str(record))
            self._log_fh.write(line + "\n")
            self._log_fh.flush()
        except OSError:
            pass  # Don't crash the lab if logging fails

    def close(self) -> None:
        """Flush and close the log file.  Call on clean shutdown."""
        if self._log_fh:
            try:
                self._log_fh.flush()
                self._log_fh.close()
            except OSError:
                pass
            self._log_fh = None

    def __del__(self):
        self.close()


# ── Singleton ─────────────────────────────────────────────────────────────────

_monitor_instance: Optional[LabMonitor] = None
_monitor_lock = threading.Lock()


def get_monitor(log_file: Optional[Path] = None) -> LabMonitor:
    """
    Return the process-wide LabMonitor singleton.

    Creates the monitor on first call.  Subsequent calls ignore ``log_file``.

    This is the **only** way components should obtain the monitor — never
    instantiate ``LabMonitor`` directly.

    Example:
        from core.lab_monitor import get_monitor, ComponentType, EventLevel
        mon = get_monitor()
        mon.register("my-component", ComponentType.POS, "My POS Terminal")
        mon.event("my-component", EventLevel.INFO, "Ready")
    """
    global _monitor_instance
    if _monitor_instance is None:
        with _monitor_lock:
            if _monitor_instance is None:
                _monitor_instance = LabMonitor(log_file=log_file)
                logger.info("LabMonitor singleton created")
    return _monitor_instance


def reset_monitor() -> None:
    """
    Destroy and recreate the singleton (useful in tests).

    Not safe to call while other threads are using the monitor.
    """
    global _monitor_instance
    with _monitor_lock:
        if _monitor_instance is not None:
            _monitor_instance.close()
        _monitor_instance = None
