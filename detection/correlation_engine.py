"""
correlation_engine.py

Purpose
-------
Correlates normalized Windows security events over time for the
Intelligent SOC Assistant.

Pipeline
--------
Windows Event Logs
        ↓
windows_event_monitor.py
        ↓
parser.py
        ↓
windows_normalizer.py
        ↓
correlation_engine.py
        ↓
detection_engine.py

Responsibilities
----------------
1. Maintain short-term event history.
2. Correlate repeated failed logons.
3. Apply configurable thresholds and time windows.
4. Suppress duplicate correlated detections using cooldowns.
5. Preserve evidence for downstream detection.
6. Provide a clean interface for future correlation rules.

Important
---------
This module does NOT:

- Assign final attack names
- Assign severity
- Map MITRE ATT&CK
- Write incidents to the database
- Generate dashboard alerts directly

Example
-------
Three Event ID 4625 events within 60 seconds:

4625
4625
4625
   ↓
ONE correlated candidate

Additional failures during the cooldown update the internal
sequence but do not repeatedly emit duplicate candidates.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Deque, Dict, List, Optional, Tuple


# ==========================================================
# Correlation Configuration
# ==========================================================

FAILED_LOGIN_THRESHOLD = 3

FAILED_LOGIN_WINDOW_SECONDS = 60

FAILED_LOGIN_COOLDOWN_SECONDS = 120


# ==========================================================
# Internal Limits
# ==========================================================

MAX_EVENTS_PER_KEY = 100


# ==========================================================
# Helper Functions
# ==========================================================

def _clean(
    value: Any
) -> Optional[str]:
    """
    Return a clean string or None.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.lower() in {
        "-",
        "none",
        "null",
        "n/a",
    }:
        return None

    return value


def _safe_int(
    value: Any
) -> Optional[int]:
    """
    Safely convert a value to int.
    """

    if value is None:
        return None

    try:
        return int(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def _parse_timestamp(
    value: Any
) -> datetime:
    """
    Convert an ISO timestamp into a timezone-aware datetime.

    If the event timestamp is unavailable or invalid, use the
    current UTC time so correlation can continue safely.
    """

    value = _clean(value)

    if value is None:
        return datetime.now(timezone.utc)

    try:

        timestamp = value

        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"

        parsed = datetime.fromisoformat(timestamp)

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (
        TypeError,
        ValueError,
    ):
        return datetime.now(timezone.utc)


def _seconds_between(
    newer: datetime,
    older: datetime,
) -> float:
    """
    Return the absolute number of seconds between timestamps.
    """

    return abs(
        (
            newer - older
        ).total_seconds()
    )


# ==========================================================
# Correlation Engine
# ==========================================================

class CorrelationEngine:
    """
    Stateful correlation engine.

    One instance should normally be kept alive for the entire
    monitoring session.

    Example:

        engine = CorrelationEngine()

        result = engine.process_event(
            normalized_event
        )

        if result:
            send_to_detection_engine(result)
    """

    def __init__(
        self,
        failed_login_threshold: int = FAILED_LOGIN_THRESHOLD,
        failed_login_window_seconds: int = FAILED_LOGIN_WINDOW_SECONDS,
        failed_login_cooldown_seconds: int = FAILED_LOGIN_COOLDOWN_SECONDS,
    ) -> None:

        self.failed_login_threshold = max(
            int(failed_login_threshold),
            2,
        )

        self.failed_login_window_seconds = max(
            int(failed_login_window_seconds),
            1,
        )

        self.failed_login_cooldown_seconds = max(
            int(failed_login_cooldown_seconds),
            1,
        )

        # Failed-login history:
        #
        # key
        #   ↓
        # deque of normalized 4625 events

        self._failed_logins: Dict[
            Tuple[str, str, str],
            Deque[Dict[str, Any]]
        ] = defaultdict(
            lambda: deque(
                maxlen=MAX_EVENTS_PER_KEY
            )
        )

        # Last time a correlated candidate was emitted
        # for a particular failed-login key.

        self._failed_login_last_alert: Dict[
            Tuple[str, str, str],
            datetime
        ] = {}

        self._lock = Lock()


    # ======================================================
    # Public Event Processor
    # ======================================================

    def process_event(
        self,
        event: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Process one normalized Windows event.

        Returns
        -------
        list

        Empty list:
            No correlation threshold reached.

        Non-empty list:
            One or more correlated candidates are ready for
            the detection engine.

        Returning a list makes this interface expandable for
        future rules.
        """

        if not isinstance(event, dict):
            return []

        event_id = _safe_int(
            event.get("event_id")
        )

        if event_id is None:
            return []

        results: List[
            Dict[str, Any]
        ] = []

        with self._lock:

            # ----------------------------------------------
            # Failed Login Correlation
            # ----------------------------------------------

            if event_id == 4625:

                result = (
                    self._correlate_failed_logins(
                        event
                    )
                )

                if result is not None:
                    results.append(result)

            # Future correlation rules will be added here.
            #
            # Example:
            #
            # elif event_id == 4798:
            #     ...
            #
            # elif event_id == 4688:
            #     ...

        return results


    # ======================================================
    # Failed Login Correlation
    # ======================================================

    def _correlate_failed_logins(
        self,
        event: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Correlate repeated Event ID 4625 events.

        Required behavior:

            Failure #1
                → store only

            Failure #2
                → store only

            Failure #3 within 60 sec
                → emit ONE correlated candidate

            Failure #4/#5 during cooldown
                → store
                → do NOT emit duplicate candidate

        Events are grouped by:

            source identity
            +
            target username
            +
            destination host

        When Windows does not provide a target username,
        "unknown" is used rather than inventing one.
        """

        event_time = _parse_timestamp(
            event.get("timestamp")
            or event.get("collected_at")
        )

        key = self._build_failed_login_key(
            event
        )

        history = self._failed_logins[
            key
        ]

        # ----------------------------------------------
        # Remove events outside the configured window
        # ----------------------------------------------

        while history:

            oldest_event = history[0]

            oldest_time = _parse_timestamp(
                oldest_event.get("timestamp")
                or oldest_event.get("collected_at")
            )

            age = _seconds_between(
                event_time,
                oldest_time,
            )

            if (
                age
                <= self.failed_login_window_seconds
            ):
                break

            history.popleft()

        # ----------------------------------------------
        # Add current failed login
        # ----------------------------------------------

        history.append(event)

        failure_count = len(history)

        # ----------------------------------------------
        # Threshold not reached
        # ----------------------------------------------

        if (
            failure_count
            < self.failed_login_threshold
        ):
            return None

        # ----------------------------------------------
        # Cooldown / Duplicate Suppression
        # ----------------------------------------------

        last_alert_time = (
            self._failed_login_last_alert.get(
                key
            )
        )

        if last_alert_time is not None:

            elapsed = _seconds_between(
                event_time,
                last_alert_time,
            )

            if (
                elapsed
                < self.failed_login_cooldown_seconds
            ):
                return None

        # ----------------------------------------------
        # Threshold reached
        # ----------------------------------------------

        first_event = history[0]

        last_event = history[-1]

        first_time = _parse_timestamp(
            first_event.get("timestamp")
            or first_event.get("collected_at")
        )

        last_time = _parse_timestamp(
            last_event.get("timestamp")
            or last_event.get("collected_at")
        )

        time_window = _seconds_between(
            last_time,
            first_time,
        )

        self._failed_login_last_alert[
            key
        ] = event_time

        return {

            # ------------------------------------------
            # Correlation Identity
            # ------------------------------------------

            "correlation_type":
                "multiple_failed_logins",

            "correlation_rule":
                "failed_login_threshold",

            # ------------------------------------------
            # Event Information
            # ------------------------------------------

            "trigger_event_id":
                4625,

            "event_category":
                "authentication",

            # ------------------------------------------
            # Threshold Information
            # ------------------------------------------

            "event_count":
                failure_count,

            "threshold":
                self.failed_login_threshold,

            "configured_window_seconds":
                self.failed_login_window_seconds,

            "observed_window_seconds":
                round(
                    time_window,
                    3
                ),

            # ------------------------------------------
            # Time
            # ------------------------------------------

            "first_seen":
                first_event.get(
                    "timestamp"
                )
                or first_event.get(
                    "collected_at"
                ),

            "last_seen":
                last_event.get(
                    "timestamp"
                )
                or last_event.get(
                    "collected_at"
                ),

            # ------------------------------------------
            # Source
            # ------------------------------------------

            "source_ip":
                event.get(
                    "source_ip"
                ),

            "source_port":
                event.get(
                    "source_port"
                ),

            "authentication_scope":
                event.get(
                    "authentication_scope"
                ),

            # ------------------------------------------
            # Target / Victim
            # ------------------------------------------

            "username":
                event.get(
                    "username"
                ),

            "domain":
                event.get(
                    "domain"
                ),

            "hostname":
                event.get(
                    "hostname"
                ),

            "host_ip":
                event.get(
                    "host_ip"
                ),

            # ------------------------------------------
            # Authentication
            # ------------------------------------------

            "logon_type":
                event.get(
                    "logon_type"
                ),

            "logon_type_name":
                event.get(
                    "logon_type_name"
                ),

            "failure_reason":
                event.get(
                    "failure_reason"
                ),

            "status":
                event.get(
                    "status"
                ),

            "sub_status":
                event.get(
                    "sub_status"
                ),

            # ------------------------------------------
            # Evidence
            # ------------------------------------------

            "record_ids": [

                item.get(
                    "record_id"
                )

                for item in history

                if item.get(
                    "record_id"
                ) is not None
            ],

            "events":
                list(
                    history
                ),

            # ------------------------------------------
            # Latest Event
            # ------------------------------------------

            "latest_event":
                event,
        }


    # ======================================================
    # Failed Login Grouping Key
    # ======================================================

    @staticmethod
    def _build_failed_login_key(
        event: Dict[str, Any],
    ) -> Tuple[str, str, str]:
        """
        Build a grouping key for failed-login correlation.

        Key:

            source
            +
            username
            +
            destination host

        For local authentication:

            source = 127.0.0.1

        For remote authentication:

            source = actual remote IP when Windows provides it.

        Missing values remain 'unknown'.
        """

        source_ip = (

            _clean(
                event.get(
                    "source_ip"
                )
            )

            or "unknown"
        )

        username = (

            _clean(
                event.get(
                    "username"
                )
            )

            or _clean(
                event.get(
                    "target_user"
                )
            )

            or "unknown"
        )

        hostname = (

            _clean(
                event.get(
                    "hostname"
                )
            )

            or _clean(
                event.get(
                    "computer"
                )
            )

            or "unknown"
        )

        return (

            source_ip.lower(),

            username.lower(),

            hostname.lower(),
        )


    # ======================================================
    # Cleanup
    # ======================================================

    def cleanup(
        self
    ) -> None:
        """
        Remove stale failed-login history and expired cooldown
        entries.

        This prevents long-running desktop sessions from
        retaining unnecessary old state.
        """

        now = datetime.now(
            timezone.utc
        )

        with self._lock:

            # ------------------------------------------
            # Clean failed-login histories
            # ------------------------------------------

            empty_keys = []

            for key, history in (
                self._failed_logins.items()
            ):

                while history:

                    oldest_event = history[0]

                    oldest_time = _parse_timestamp(

                        oldest_event.get(
                            "timestamp"
                        )

                        or oldest_event.get(
                            "collected_at"
                        )
                    )

                    age = _seconds_between(
                        now,
                        oldest_time,
                    )

                    if (
                        age
                        <= self.failed_login_window_seconds
                    ):
                        break

                    history.popleft()

                if not history:
                    empty_keys.append(
                        key
                    )

            for key in empty_keys:

                self._failed_logins.pop(
                    key,
                    None
                )

            # ------------------------------------------
            # Clean expired cooldowns
            # ------------------------------------------

            expired_alert_keys = []

            for key, alert_time in (
                self._failed_login_last_alert.items()
            ):

                age = _seconds_between(
                    now,
                    alert_time,
                )

                if (
                    age
                    >= self.failed_login_cooldown_seconds
                ):

                    expired_alert_keys.append(
                        key
                    )

            for key in expired_alert_keys:

                self._failed_login_last_alert.pop(
                    key,
                    None
                )


    # ======================================================
    # Reset
    # ======================================================

    def reset(
        self
    ) -> None:
        """
        Reset all in-memory correlation state.

        Useful during controlled development testing.

        This does NOT modify Windows Event Logs or the
        state/last_record.txt checkpoint.
        """

        with self._lock:

            self._failed_logins.clear()

            self._failed_login_last_alert.clear()


    # ======================================================
    # Statistics
    # ======================================================

    def get_statistics(
        self
    ) -> Dict[str, Any]:
        """
        Return basic runtime correlation statistics.

        This may later be displayed in the desktop dashboard.
        """

        with self._lock:

            tracked_sequences = len(
                self._failed_logins
            )

            tracked_failed_events = sum(

                len(history)

                for history
                in self._failed_logins.values()
            )

            active_cooldowns = len(
                self._failed_login_last_alert
            )

        return {

            "failed_login_threshold":
                self.failed_login_threshold,

            "failed_login_window_seconds":
                self.failed_login_window_seconds,

            "failed_login_cooldown_seconds":
                self.failed_login_cooldown_seconds,

            "tracked_sequences":
                tracked_sequences,

            "tracked_failed_events":
                tracked_failed_events,

            "active_cooldowns":
                active_cooldowns,
        }


# ==========================================================
# Development Output
# ==========================================================

def print_correlated_event(
    correlation: Dict[str, Any],
) -> None:
    """
    Print a correlated candidate during development.

    This is NOT yet the final dashboard incident.
    """

    print()

    print(
        "=" * 72
    )

    print(
        "CORRELATED SECURITY EVENT"
    )

    print(
        "=" * 72
    )

    fields = [

        "correlation_type",
        "correlation_rule",

        "trigger_event_id",

        "event_count",
        "threshold",

        "configured_window_seconds",
        "observed_window_seconds",

        "first_seen",
        "last_seen",

        "source_ip",
        "authentication_scope",

        "username",
        "domain",

        "hostname",
        "host_ip",

        "logon_type",
        "logon_type_name",

        "failure_reason",
        "status",
        "sub_status",

        "record_ids",
    ]

    for field in fields:

        value = correlation.get(
            field
        )

        if value is not None:

            print(
                f"{field:<28}: {value}"
            )

    print(
        "=" * 72
    )


# ==========================================================
# Standalone Unit Test
# ==========================================================

def _run_test() -> None:
    """
    Test the three-failed-login correlation rule without
    requiring real Windows logons.
    """

    engine = CorrelationEngine(

        failed_login_threshold=3,

        failed_login_window_seconds=60,

        failed_login_cooldown_seconds=120,
    )

    test_events = [

        {
            "event_id": 4625,
            "record_id": 1001,
            "timestamp":
                "2026-07-20T18:00:00+00:00",

            "source_ip":
                "127.0.0.1",

            "username":
                "testuser",

            "hostname":
                "TEST-PC",

            "host_ip":
                "192.168.1.20",

            "authentication_scope":
                "local",

            "logon_type":
                2,

            "logon_type_name":
                "Interactive",
        },

        {
            "event_id": 4625,
            "record_id": 1002,
            "timestamp":
                "2026-07-20T18:00:05+00:00",

            "source_ip":
                "127.0.0.1",

            "username":
                "testuser",

            "hostname":
                "TEST-PC",

            "host_ip":
                "192.168.1.20",

            "authentication_scope":
                "local",

            "logon_type":
                2,

            "logon_type_name":
                "Interactive",
        },

        {
            "event_id": 4625,
            "record_id": 1003,
            "timestamp":
                "2026-07-20T18:00:10+00:00",

            "source_ip":
                "127.0.0.1",

            "username":
                "testuser",

            "hostname":
                "TEST-PC",

            "host_ip":
                "192.168.1.20",

            "authentication_scope":
                "local",

            "logon_type":
                2,

            "logon_type_name":
                "Interactive",
        },

    ]

    print()
    print(
        "Correlation Engine Test"
    )
    print(
        "-" * 40
    )

    for index, event in enumerate(
        test_events,
        start=1,
    ):

        results = engine.process_event(
            event
        )

        print(
            f"Failed attempt #{index}: "
            f"correlations={len(results)}"
        )

        for result in results:

            print_correlated_event(
                result
            )

    print()

    print(
        "Statistics:"
    )

    print(
        engine.get_statistics()
    )


if __name__ == "__main__":

    _run_test()