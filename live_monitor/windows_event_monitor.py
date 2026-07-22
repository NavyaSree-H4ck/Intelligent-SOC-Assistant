"""
windows_event_monitor.py

Purpose
-------
Live Windows Event Log collector for the Intelligent SOC Assistant.

Responsibilities
----------------
1. Read Windows Event Logs continuously.
2. Monitor selected Windows Event Log channels.
3. Collect only security-relevant Event IDs.
4. Render each event as XML.
5. Send collected events to a callback function.
6. Track the last successfully processed Event Record ID.
7. Support clean start and stop operations.
8. Work later with the PySide6 desktop application.

Important
---------
This module performs LOG COLLECTION ONLY.

It does NOT:
- Detect attacks
- Assign severity
- Perform MITRE mapping
- Generate recommendations
- Invent source IP addresses
- Parse security fields from XML

Those responsibilities belong to later modules.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional

import win32evtlog
import pywintypes

from live_monitor.state_manager import (
    get_last_record,
    save_last_record,
)

from parser.parser import (
    parse_event,
)

from normalizer.windows_normalizer import (
    normalize_windows_event,
)
from detection.correlation_engine import (
    CorrelationEngine,
)

from detection.detection_engine import (
    DetectionEngine,
)

from severity.severity import (
    SeverityEngine,
)

from mitre.live_mitre_mapper import (
    MitreMapper,
)

from recommendation.recommendation import (
    RecommendationEngine,
)

from database.database import (
    DatabaseManager,
)

# ==========================================================
# Event IDs We Want to Collect
# ==========================================================

SECURITY_EVENT_IDS = {

    # Authentication
    4624,   # Successful logon
    4625,   # Failed logon
    4648,   # Logon using explicit credentials

    # Privileges
    4672,   # Special privileges assigned to new logon

    # Process execution
    4688,   # New process created

    # Account management
    4720,   # User account created
    4726,   # User account deleted

    # Group membership changes
    4728,
    4732,

    # Account / group discovery
    4798,

    # Audit log cleared
    1102,

    # Windows Filtering Platform connection
    5156,
}


POWERSHELL_EVENT_IDS = {

    4103,   # PowerShell module logging
    4104,   # PowerShell script block logging
}


# ==========================================================
# Channels
# ==========================================================

MONITORED_CHANNELS = {

    "Security": SECURITY_EVENT_IDS,

    "Microsoft-Windows-PowerShell/Operational":
        POWERSHELL_EVENT_IDS,
}


# ==========================================================
# Type Alias
# ==========================================================

EventCallback = Callable[
    [Dict[str, Any]],
    None
]


# ==========================================================
# Windows Event Monitor
# ==========================================================

class WindowsEventMonitor:
    """
    Continuously monitors selected Windows Event Log channels.

    The monitor is designed so that it can later run behind
    the PySide6 desktop dashboard without freezing the GUI.
    """

    def __init__(
        self,
        event_callback: Optional[EventCallback] = None,
        poll_interval: float = 1.0,
        start_from_current: bool = True,
    ) -> None:

        """
        Parameters
        ----------
        event_callback:
            Function called whenever a relevant Windows event
            is collected.

        poll_interval:
            Delay between polling cycles.

        start_from_current:
            If True and no saved checkpoint exists for a channel,
            monitoring starts from the channel's current newest
            record instead of replaying the entire historical log.

            This is the recommended behavior for live monitoring.
        """

        self.event_callback = event_callback

        self.poll_interval = max(
            float(poll_interval),
            0.2
        )

        self.start_from_current = bool(
            start_from_current
        )

        self._running = False

        self._threads: Dict[
            str,
            threading.Thread
        ] = {}

        self._stop_event = threading.Event()

        self._lock = threading.Lock()

        self._channel_status: Dict[
            str,
            Dict[str, Any]
        ] = {}


    # ======================================================
    # Public Status
    # ======================================================

    @property
    def is_running(self) -> bool:
        """
        Return True when monitoring is active.
        """

        return self._running


    def get_channel_status(
        self
    ) -> Dict[str, Dict[str, Any]]:

        """
        Return a copy of the current channel status.

        This will later be useful for the desktop dashboard.
        """

        with self._lock:

            return {

                channel: dict(status)

                for channel, status
                in self._channel_status.items()
            }


    # ======================================================
    # Start Monitoring
    # ======================================================

    def start(self) -> None:
        """
        Start monitoring all configured channels.

        Each Windows Event Log channel runs in its own
        background thread.
        """

        if self._running:

            print(
                "[MONITOR] Monitoring is already running."
            )

            return

        self._running = True

        self._stop_event.clear()

        print()
        print(
            "=============================================="
        )
        print(
            " Intelligent SOC Assistant"
        )
        print(
            " Windows Event Monitoring Started"
        )
        print(
            "=============================================="
        )
        print()

        for channel, event_ids in MONITORED_CHANNELS.items():

            thread = threading.Thread(

                target=self._monitor_channel,

                args=(
                    channel,
                    event_ids,
                ),

                name=f"SOCMonitor-{channel}",

                daemon=True,
            )

            self._threads[
                channel
            ] = thread

            thread.start()

        print(
            "[MONITOR] Live monitoring is active."
        )

        print(
            "[MONITOR] Press Ctrl+C to stop."
        )

        print()


    # ======================================================
    # Stop Monitoring
    # ======================================================

    def stop(self) -> None:
        """
        Stop all monitoring threads gracefully.
        """

        if not self._running:

            return

        print()
        print(
            "[MONITOR] Stopping Windows Event Monitoring..."
        )

        self._running = False

        self._stop_event.set()

        for thread in list(
            self._threads.values()
        ):

            if thread.is_alive():

                thread.join(
                    timeout=5
                )

        self._threads.clear()

        print(
            "[MONITOR] Monitoring stopped successfully."
        )


    # ======================================================
    # Update Channel Status
    # ======================================================

    def _update_channel_status(
        self,
        channel: str,
        **values: Any,
    ) -> None:

        """
        Update runtime information for one monitored channel.
        """

        with self._lock:

            if channel not in self._channel_status:

                self._channel_status[
                    channel
                ] = {}

            self._channel_status[
                channel
            ].update(
                values
            )


    # ======================================================
    # Get Current Newest Record ID
    # ======================================================

    def _get_current_record_id(
        self,
        channel: str,
    ) -> int:

        """
        Return the newest Event Record ID currently available
        in a Windows Event Log channel.

        Returns 0 if the channel cannot be queried.
        """

        query_handle = None

        try:

            query_handle = win32evtlog.EvtQuery(

                channel,

                win32evtlog.EvtQueryChannelPath,

                "*",

                None,
            )

            events = win32evtlog.EvtNext(

                query_handle,

                1,

                0,

                0,
            )

            if not events:

                return 0

            # EvtQuery normally returns oldest-to-newest unless
            # reverse direction is explicitly requested.
            #
            # Therefore query again in reverse direction to get
            # the newest record efficiently.

            try:

                win32evtlog.EvtClose(
                    events[0]
                )

            except Exception:

                pass

            win32evtlog.EvtClose(
                query_handle
            )

            query_handle = None

            reverse_handle = win32evtlog.EvtQuery(

                channel,

                win32evtlog.EvtQueryChannelPath
                | win32evtlog.EvtQueryReverseDirection,

                "*",

                None,
            )

            events = win32evtlog.EvtNext(

                reverse_handle,

                1,

                0,

                0,
            )

            if not events:

                win32evtlog.EvtClose(
                    reverse_handle
                )

                return 0

            xml = win32evtlog.EvtRender(

                events[0],

                win32evtlog.EvtRenderEventXml,
            )

            record_id = self._extract_record_id_from_xml(
                xml
            )

            try:

                win32evtlog.EvtClose(
                    events[0]
                )

            except Exception:

                pass

            win32evtlog.EvtClose(
                reverse_handle
            )

            return record_id

        except pywintypes.error:

            return 0

        except Exception:

            return 0

        finally:

            if query_handle is not None:

                try:

                    win32evtlog.EvtClose(
                        query_handle
                    )

                except Exception:

                    pass


    # ======================================================
    # Lightweight XML Record-ID Extraction
    # ======================================================

    @staticmethod
    def _extract_record_id_from_xml(
        xml: str,
    ) -> int:

        """
        Extract EventRecordID from XML.

        This is used only by the collector for checkpointing.

        Full XML parsing belongs to parser/parser.py.
        """

        try:

            start_tag = "<EventRecordID>"

            end_tag = "</EventRecordID>"

            start = xml.find(
                start_tag
            )

            if start == -1:

                return 0

            start += len(
                start_tag
            )

            end = xml.find(
                end_tag,
                start
            )

            if end == -1:

                return 0

            return int(
                xml[
                    start:end
                ].strip()
            )

        except (
            TypeError,
            ValueError,
            AttributeError
        ):

            return 0


    # ======================================================
    # Monitor One Channel
    # ======================================================

    def _monitor_channel(
        self,
        channel: str,
        event_ids: set[int],
    ) -> None:

        """
        Continuously monitor one Windows Event Log channel.
        """

        self._update_channel_status(

            channel,

            status="Starting",

            last_record=0,

            last_event_time=None,

            error=None,
        )

        print(
            f"[CHANNEL] Starting: {channel}"
        )

        try:

            last_record = get_last_record(
                channel
            )

            # --------------------------------------------------
            # First-run behavior
            # --------------------------------------------------

            if (
                last_record == 0
                and self.start_from_current
            ):

                current_record = (
                    self._get_current_record_id(
                        channel
                    )
                )

                if current_record > 0:

                    save_last_record(

                        current_record,

                        channel
                    )

                    last_record = current_record

                    print(
                        f"[CHANNEL] {channel}"
                        f" initialized at current "
                        f"record {current_record}."
                    )

            self._update_channel_status(

                channel,

                status="Live",

                last_record=last_record,

                error=None,
            )

            # --------------------------------------------------
            # Continuous monitoring loop
            # --------------------------------------------------

            while (
                self._running
                and not self._stop_event.is_set()
            ):

                try:

                    newest_processed = (
                        self._read_new_events(
                            channel=channel,
                            event_ids=event_ids,
                            last_record=last_record,
                        )
                    )

                    if newest_processed > last_record:

                        last_record = newest_processed

                        save_last_record(

                            last_record,

                            channel
                        )

                        self._update_channel_status(

                            channel,

                            status="Live",

                            last_record=last_record,

                            error=None,
                        )

                except pywintypes.error as error:

                    message = str(
                        error
                    )

                    self._update_channel_status(

                        channel,

                        status="Error",

                        error=message,
                    )

                    print(
                        f"[CHANNEL ERROR] "
                        f"{channel}: {message}"
                    )

                except Exception as error:

                    message = str(
                        error
                    )

                    self._update_channel_status(

                        channel,

                        status="Error",

                        error=message,
                    )

                    print(
                        f"[CHANNEL ERROR] "
                        f"{channel}: {message}"
                    )

                self._stop_event.wait(
                    self.poll_interval
                )

        except Exception as error:

            self._update_channel_status(

                channel,

                status="Error",

                error=str(error),
            )

            print(
                f"[CHANNEL ERROR] "
                f"Unable to monitor {channel}: {error}"
            )

        finally:

            current_status = (
                self.get_channel_status()
                .get(
                    channel,
                    {}
                )
            )

            # Do not overwrite useful error information
            # until the monitor is actually stopped.

            if not self._running:

                self._update_channel_status(

                    channel,

                    status="Stopped",
                )

            elif current_status.get(
                "status"
            ) != "Error":

                self._update_channel_status(

                    channel,

                    status="Stopped",
                )


    # ======================================================
    # Read New Events
    # ======================================================

    def _read_new_events(
        self,
        channel: str,
        event_ids: set[int],
        last_record: int,
    ) -> int:

        """
        Query and process events newer than last_record.

        Returns the highest Event Record ID successfully
        observed during this polling cycle.
        """

        query_handle = None

        highest_record = last_record

        # --------------------------------------------------
        # Query only events newer than our checkpoint.
        #
        # We intentionally query all newer events, not only
        # interesting Event IDs.
        #
        # This allows the checkpoint to move forward even when
        # Windows generates unrelated events.
        # --------------------------------------------------

        if last_record > 0:

            query = (
                f"*[System[EventRecordID > "
                f"{int(last_record)}]]"
            )

        else:

            query = "*"

        try:

            query_handle = win32evtlog.EvtQuery(

                channel,

                win32evtlog.EvtQueryChannelPath,

                query,

                None,
            )

            while (
                self._running
                and not self._stop_event.is_set()
            ):

                events = win32evtlog.EvtNext(

                    query_handle,

                    64,

                    0,

                    0,
                )

                if not events:

                    break

                for event_handle in events:

                    try:

                        xml = win32evtlog.EvtRender(

                            event_handle,

                            win32evtlog.EvtRenderEventXml,
                        )

                        record_id = (
                            self._extract_record_id_from_xml(
                                xml
                            )
                        )

                        if record_id > highest_record:

                            highest_record = record_id

                        # The full parser will extract the Event ID.
                        #
                        # For collector filtering, we use a small,
                        # safe extraction helper.

                        event_id = (
                            self._extract_event_id_from_xml(
                                xml
                            )
                        )

                        if event_id not in event_ids:

                            continue

                        collected_event = {

                            "event_id":
                                event_id,

                            "record_id":
                                record_id,

                            "channel":
                                channel,

                            "collected_at":
                                datetime.now()
                                .astimezone()
                                .isoformat(),

                            "xml":
                                xml,
                        }

                        self._handle_event(
                            collected_event
                        )

                        self._update_channel_status(

                            channel,

                            status="Live",

                            last_record=record_id,

                            last_event_time=(
                                collected_event[
                                    "collected_at"
                                ]
                            ),

                            error=None,
                        )

                    finally:

                        try:

                            win32evtlog.EvtClose(
                                event_handle
                            )

                        except Exception:

                            pass

            return highest_record

        finally:

            if query_handle is not None:

                try:

                    win32evtlog.EvtClose(
                        query_handle
                    )

                except Exception:

                    pass


    # ======================================================
    # Lightweight Event-ID Extraction
    # ======================================================

    @staticmethod
    def _extract_event_id_from_xml(
        xml: str,
    ) -> int:

        """
        Extract EventID from Windows Event XML.

        Full parsing is intentionally deferred to parser.py.
        """

        try:

            start_tag = "<EventID"

            start = xml.find(
                start_tag
            )

            if start == -1:

                return 0

            start = xml.find(
                ">",
                start
            )

            if start == -1:

                return 0

            start += 1

            end = xml.find(
                "</EventID>",
                start
            )

            if end == -1:

                return 0

            return int(
                xml[
                    start:end
                ].strip()
            )

        except (
            TypeError,
            ValueError,
            AttributeError
        ):

            return 0


    # ======================================================
    # Handle Collected Event
    # ======================================================

    def _handle_event(
        self,
        event: Dict[str, Any],
    ) -> None:

        """
        Send a collected event to the configured callback.

        If no callback is configured, print a concise summary.
        """

        if self.event_callback is not None:

            try:

                self.event_callback(
                    event
                )

            except Exception as error:

                print(
                    "[CALLBACK ERROR] "
                    f"{error}"
                )

        else:

            print(
                "[EVENT] "
                f"Channel={event.get('channel')} | "
                f"EventID={event.get('event_id')} | "
                f"RecordID={event.get('record_id')} | "
                f"Collected={event.get('collected_at')}"
            )

correlation_engine = CorrelationEngine(

    failed_login_threshold=3,

    failed_login_window_seconds=60,

    failed_login_cooldown_seconds=120,
) 

detection_engine = DetectionEngine()

severity_engine = SeverityEngine()

mitre_mapper = MitreMapper()

recommendation_engine = RecommendationEngine()
database_manager = DatabaseManager()

database_manager.initialize_database()


def process_detection(
    detection: Dict[str, Any],
) -> None:
    """
    Enrich and persist one security detection.

    Detection
        ↓
    Severity
        ↓
    MITRE ATT&CK
        ↓
    Recommendations
        ↓
    SQLite Database
    """

    try:

        # ==================================================
        # 1. Severity
        # ==================================================

        enriched_detection = (
            severity_engine.evaluate(
                detection
            )
        )

        # ==================================================
        # 2. MITRE ATT&CK
        # ==================================================

        enriched_detection = (
            mitre_mapper.map_detection(
                enriched_detection
            )
        )

        # ==================================================
        # 3. Recommendations
        # ==================================================

        enriched_detection = (
            recommendation_engine.generate(
                enriched_detection
            )
        )

        # ==================================================
        # 4. Database
        # ==================================================

        incident_id = (
            database_manager.insert_incident(
                enriched_detection
            )
        )

        # ==================================================
        # 5. Minimal Console Confirmation
        # ==================================================

        print()

        print(
            "=" * 76
        )

        print(
            "SECURITY INCIDENT CREATED"
        )

        print(
            "=" * 76
        )

        print(
            f"Incident ID       : "
            f"{incident_id}"
        )

        print(
            f"Detection         : "
            f"{enriched_detection.get('detection_type')}"
        )

        print(
            f"Severity          : "
            f"{enriched_detection.get('severity')}"
        )

        print(
            f"Risk Score        : "
            f"{enriched_detection.get('risk_score')}"
        )

        print(
            f"Response Priority : "
            f"{enriched_detection.get('response_priority')}"
        )

        print(
            f"Source IP         : "
            f"{enriched_detection.get('source_ip')}"
        )

        print(
            f"Host              : "
            f"{enriched_detection.get('hostname')}"
        )

        print(
            f"MITRE Technique   : "
            f"{enriched_detection.get('mitre_technique_id')}"
        )

        print(
            "Database Status   : STORED"
        )

        print(
            "=" * 76
        )

    except Exception as error:

        print()

        print(
            "[PIPELINE ERROR] "
            "Failed to enrich/store detection:"
        )

        print(
            error
        )
        
# ==========================================================
# Standalone Test Callback
# ==========================================================

def process_event_for_testing(
    event: Dict[str, Any],
) -> None:
    """
    Live SOC processing pipeline.

    Raw Windows Event
            ↓
    Parser
            ↓
    Normalizer
            ↓
      ┌─────┴─────┐
      ↓           ↓
    Direct     Correlation
    Detection     ↓
      │       Detection
      └─────┬─────┘
            ↓
    process_detection()
            ↓
    Severity
            ↓
    MITRE ATT&CK
            ↓
    Recommendations
            ↓
    SQLite Database
    """

    # ======================================================
    # 1. Parse
    # ======================================================

    parsed_event = parse_event(
        event
    )

    if parsed_event is None:

        print(
            "[PIPELINE ERROR] "
            "Event parsing failed."
        )

        return

    # ======================================================
    # 2. Normalize
    # ======================================================

    normalized_event = normalize_windows_event(
        parsed_event
    )

    if normalized_event is None:

        print(
            "[PIPELINE ERROR] "
            "Event normalization failed."
        )

        return

    # ======================================================
    # 3. Direct / Single-Event Detection
    # ======================================================

    direct_detections = (
        detection_engine.process_event(
            normalized_event
        )
    )

    for detection in direct_detections:

        process_detection(
            detection
        )

    # ======================================================
    # 4. Multi-Event Correlation
    # ======================================================

    correlated_events = (
        correlation_engine.process_event(
            normalized_event
        )
    )

    # ======================================================
    # 5. Detection From Correlation
    # ======================================================

    for correlated_event in correlated_events:

        correlated_detections = (
            detection_engine.process_correlation(
                correlated_event
            )
        )

        for detection in correlated_detections:

            process_detection(
                detection
            )
# ==========================================================
# Standalone Execution
# ==========================================================

def main() -> None:

    """
    Run the Windows Event Monitor directly for testing.
    """

    monitor = WindowsEventMonitor(

        event_callback=process_event_for_testing,

        poll_interval=1.0,

        start_from_current=True,
    )

    try:

        monitor.start()

        while monitor.is_running:

            time.sleep(
                1
            )

    except KeyboardInterrupt:

        print()
        print(
            "[SYSTEM] Ctrl+C received."
        )

    finally:

        monitor.stop()


if __name__ == "__main__":

    main()