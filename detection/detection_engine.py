"""
detection_engine.py

Purpose
-------
Security detection engine for the Intelligent SOC Assistant.

Pipeline
--------
Windows Event Logs
        ↓
Collector
        ↓
Parser
        ↓
Normalizer
        ↓
Correlation Engine
        ↓
Detection Engine
        ↓
Severity Engine
        ↓
MITRE ATT&CK
        ↓
Recommendations
        ↓
Database
        ↓
Desktop Dashboard

Responsibilities
----------------
1. Convert correlated security behavior into detections.
2. Detect selected high-value single-event behaviors.
3. Distinguish local authentication failures from remote
   brute-force-like activity.
4. Detect suspicious PowerShell and command execution.
5. Detect security-sensitive account/service/task changes.
6. Avoid treating noisy events as attacks automatically.

Important
---------
This module does NOT:

- Assign final severity
- Map MITRE ATT&CK
- Write to database
- Generate reports
- Display dashboard alerts directly

Those responsibilities belong to later modules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import os
import re


# ==========================================================
# Detection Types
# ==========================================================

DETECTION_REPEATED_LOCAL_FAILURES = (
    "Repeated Local Authentication Failures"
)

DETECTION_POTENTIAL_BRUTE_FORCE = (
    "Potential Brute Force"
)

DETECTION_SUSPICIOUS_POWERSHELL = (
    "Suspicious PowerShell Activity"
)

DETECTION_SUSPICIOUS_COMMAND = (
    "Suspicious Command Execution"
)

DETECTION_USER_CREATED = (
    "User Account Created"
)

DETECTION_USER_DELETED = (
    "User Account Deleted"
)

DETECTION_GROUP_MODIFICATION = (
    "Security Group Membership Modified"
)

DETECTION_SERVICE_INSTALLED = (
    "New Service Installed"
)

DETECTION_SCHEDULED_TASK = (
    "Scheduled Task Created"
)

DETECTION_AUDIT_LOG_CLEARED = (
    "Security Audit Log Cleared"
)


# ==========================================================
# Suspicious PowerShell Indicators
# ==========================================================

POWERSHELL_INDICATORS = {

    "encodedcommand":
        "Encoded PowerShell command",

    "-enc":
        "Encoded PowerShell argument",

    "frombase64string":
        "Base64 decoding",

    "invoke-expression":
        "Dynamic PowerShell expression execution",

    "iex":
        "PowerShell Invoke-Expression alias",

    "downloadstring":
        "Remote content download",

    "downloadfile":
        "Remote file download",

    "invoke-webrequest":
        "Web request from PowerShell",

    "iwr":
        "PowerShell web request alias",

    "start-bitstransfer":
        "BITS file transfer",

    "new-object net.webclient":
        "WebClient object creation",

    "system.net.webclient":
        "WebClient usage",

    "invoke-restmethod":
        "REST request from PowerShell",

    "irm":
        "PowerShell Invoke-RestMethod alias",

    "bypass":
        "Execution policy bypass",

    "hidden":
        "Hidden execution",

    "windowstyle hidden":
        "Hidden PowerShell window",

    "reflection.assembly":
        "In-memory .NET assembly loading",
}


# ==========================================================
# Suspicious Command Patterns
# ==========================================================

SUSPICIOUS_COMMAND_PATTERNS = [

    (
        re.compile(
            r"\bvssadmin(?:\.exe)?\b.*\bdelete\b.*\bshadows\b",
            re.IGNORECASE,
        ),
        "Shadow copies deletion command",
    ),

    (
        re.compile(
            r"\bwmic(?:\.exe)?\b.*\bshadowcopy\b.*\bdelete\b",
            re.IGNORECASE,
        ),
        "Shadow copies deletion through WMIC",
    ),

    (
        re.compile(
            r"\bwbadmin(?:\.exe)?\b.*\bdelete\b",
            re.IGNORECASE,
        ),
        "Backup deletion command",
    ),

    (
        re.compile(
            r"\bbcdedit(?:\.exe)?\b.*recoveryenabled\s+no",
            re.IGNORECASE,
        ),
        "Windows recovery disabled",
    ),

    (
        re.compile(
            r"\bbcdedit(?:\.exe)?\b.*bootstatuspolicy",
            re.IGNORECASE,
        ),
        "Boot recovery policy modified",
    ),

    (
        re.compile(
            r"\bwevtutil(?:\.exe)?\b\s+cl\b",
            re.IGNORECASE,
        ),
        "Windows event log clearing command",
    ),

    (
        re.compile(
            r"\bnet(?:1)?(?:\.exe)?\b\s+user\b.*\s+/add\b",
            re.IGNORECASE,
        ),
        "User account creation command",
    ),

    (
        re.compile(
            r"\bnet(?:1)?(?:\.exe)?\b\s+localgroup\b.*\s+/add\b",
            re.IGNORECASE,
        ),
        "Local group membership modification command",
    ),

    (
        re.compile(
            r"\bschtasks(?:\.exe)?\b.*\s/create\b",
            re.IGNORECASE,
        ),
        "Scheduled task creation command",
    ),

]


# ==========================================================
# Utility Functions
# ==========================================================

def _clean(
    value: Any,
) -> Optional[str]:
    """
    Return a cleaned string or None.
    """

    if value is None:

        return None

    value = str(
        value
    ).strip()

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
    value: Any,
) -> Optional[int]:
    """
    Convert a value safely to integer.
    """

    if value is None:

        return None

    try:

        return int(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


def _now_iso() -> str:
    """
    Return current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


def _is_loopback(
    ip_address: Optional[str],
) -> bool:
    """
    Determine whether an IP represents localhost.
    """

    ip_address = _clean(
        ip_address
    )

    if ip_address is None:

        return False

    return ip_address.lower() in {

        "127.0.0.1",
        "::1",
        "localhost",

    }


def _basename(
    path: Optional[str],
) -> Optional[str]:
    """
    Return lowercase executable basename.
    """

    path = _clean(
        path
    )

    if path is None:

        return None

    path = path.replace(
        "/",
        "\\"
    )

    return os.path.basename(
        path
    ).lower()


# ==========================================================
# Detection Builder
# ==========================================================

def _build_detection(
    *,
    detection_type: str,
    detection_category: str,
    description: str,
    source_event: Optional[Dict[str, Any]] = None,
    correlation: Optional[Dict[str, Any]] = None,
    evidence: Optional[List[str]] = None,
    confidence: str = "medium",
) -> Dict[str, Any]:
    """
    Build one consistent detection object.

    Severity is intentionally not assigned here.
    """

    source_event = (
        source_event
        or {}
    )

    correlation = (
        correlation
        or {}
    )

    latest_event = (
        correlation.get(
            "latest_event"
        )
        or source_event
    )

    return {

        # ==================================================
        # Detection Identity
        # ==================================================

        "detection_type":
            detection_type,

        "detection_category":
            detection_category,

        "description":
            description,

        "confidence":
            confidence,

        "detected_at":
            _now_iso(),

        # ==================================================
        # Source Event
        # ==================================================

        "event_id":
            latest_event.get(
                "event_id"
            ),

        "event_name":
            latest_event.get(
                "event_name"
            ),

        "record_id":
            latest_event.get(
                "record_id"
            ),

        # ==================================================
        # Event Time
        # ==================================================

        "event_timestamp":
            latest_event.get(
                "timestamp"
            ),

        "first_seen":
            correlation.get(
                "first_seen"
            )
            or latest_event.get(
                "timestamp"
            ),

        "last_seen":
            correlation.get(
                "last_seen"
            )
            or latest_event.get(
                "timestamp"
            ),

        # ==================================================
        # Source / Network
        # ==================================================

        "source_ip":
            correlation.get(
                "source_ip"
            )
            or latest_event.get(
                "source_ip"
            ),

        "source_port":
            correlation.get(
                "source_port"
            )
            or latest_event.get(
                "source_port"
            ),

        "authentication_scope":
            correlation.get(
                "authentication_scope"
            )
            or latest_event.get(
                "authentication_scope"
            ),

        # ==================================================
        # Target / Host
        # ==================================================

        "hostname":
            correlation.get(
                "hostname"
            )
            or latest_event.get(
                "hostname"
            ),

        "host_ip":
            correlation.get(
                "host_ip"
            )
            or latest_event.get(
                "host_ip"
            ),

        "username":
            correlation.get(
                "username"
            )
            or latest_event.get(
                "username"
            ),

        "domain":
            correlation.get(
                "domain"
            )
            or latest_event.get(
                "domain"
            ),

        # ==================================================
        # Process
        # ==================================================

        "process_name":
            latest_event.get(
                "process_name"
            ),

        "parent_process_name":
            latest_event.get(
                "parent_process_name"
            ),

        "command_line":
            latest_event.get(
                "command_line"
            ),

        # ==================================================
        # Authentication
        # ==================================================

        "logon_type":
            latest_event.get(
                "logon_type"
            ),

        "logon_type_name":
            latest_event.get(
                "logon_type_name"
            ),

        "failure_reason":
            latest_event.get(
                "failure_reason"
            ),

        "status":
            latest_event.get(
                "status"
            ),

        "sub_status":
            latest_event.get(
                "sub_status"
            ),

        # ==================================================
        # Correlation
        # ==================================================

        "correlation_type":
            correlation.get(
                "correlation_type"
            ),

        "event_count":
            correlation.get(
                "event_count"
            ),

        "threshold":
            correlation.get(
                "threshold"
            ),

        "observed_window_seconds":
            correlation.get(
                "observed_window_seconds"
            ),

        "record_ids":
            correlation.get(
                "record_ids"
            )
            or (
                [
                    latest_event.get(
                        "record_id"
                    )
                ]
                if latest_event.get(
                    "record_id"
                )
                is not None
                else []
            ),

        # ==================================================
        # Detection Evidence
        # ==================================================

        "evidence":
            evidence
            or [],

        # ==================================================
        # Original Objects
        # ==================================================

        "source_event":
            latest_event,

        "correlation":
            correlation
            if correlation
            else None,
    }


# ==========================================================
# Detection Engine
# ==========================================================

class DetectionEngine:
    """
    Main security detection engine.
    """

    # ======================================================
    # Correlated Event Detection
    # ======================================================

    def process_correlation(
        self,
        correlation: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Convert a correlation result into security detections.
        """

        if not isinstance(
            correlation,
            dict
        ):

            return []

        correlation_type = _clean(

            correlation.get(
                "correlation_type"
            )
        )

        if correlation_type is None:

            return []

        detections: List[
            Dict[str, Any]
        ] = []

        # --------------------------------------------------
        # Multiple Failed Logins
        # --------------------------------------------------

        if (
            correlation_type
            == "multiple_failed_logins"
        ):

            detection = (
                self._detect_multiple_failed_logins(
                    correlation
                )
            )

            if detection is not None:

                detections.append(
                    detection
                )

        return detections


    # ======================================================
    # Normalized Event Detection
    # ======================================================

    def process_event(
        self,
        event: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Detect security-relevant behavior from one normalized
        Windows event.

        This is used for detections that do not require a
        multi-event threshold.
        """

        if not isinstance(
            event,
            dict
        ):

            return []

        event_id = _safe_int(

            event.get(
                "event_id"
            )
        )

        if event_id is None:

            return []

        detections: List[
            Dict[str, Any]
        ] = []

        # --------------------------------------------------
        # PowerShell
        # --------------------------------------------------

        if event_id in {

            4103,
            4104,

        }:

            detection = (
                self._detect_suspicious_powershell(
                    event
                )
            )

            if detection is not None:

                detections.append(
                    detection
                )

        # --------------------------------------------------
        # Process Creation
        # --------------------------------------------------

        elif event_id == 4688:

            detection = (
                self._detect_suspicious_command(
                    event
                )
            )

            if detection is not None:

                detections.append(
                    detection
                )

        # --------------------------------------------------
        # User Account Created
        # --------------------------------------------------

        elif event_id == 4720:

            detections.append(

                _build_detection(

                    detection_type=(
                        DETECTION_USER_CREATED
                    ),

                    detection_category=(
                        "account_management"
                    ),

                    description=(
                        "A Windows user account "
                        "was created."
                    ),

                    source_event=event,

                    evidence=[

                        (
                            "Windows Event ID 4720 "
                            "was recorded."
                        ),

                        (
                            "Target account: "
                            f"{event.get('target_user')}"
                        ),
                    ],

                    confidence="high",
                )
            )

        # --------------------------------------------------
        # User Account Deleted
        # --------------------------------------------------

        elif event_id == 4726:

            detections.append(

                _build_detection(

                    detection_type=(
                        DETECTION_USER_DELETED
                    ),

                    detection_category=(
                        "account_management"
                    ),

                    description=(
                        "A Windows user account "
                        "was deleted."
                    ),

                    source_event=event,

                    evidence=[

                        (
                            "Windows Event ID 4726 "
                            "was recorded."
                        ),

                        (
                            "Target account: "
                            f"{event.get('target_user')}"
                        ),
                    ],

                    confidence="high",
                )
            )

        # --------------------------------------------------
        # Security Group Modification
        # --------------------------------------------------

                # --------------------------------------------------
        # Sensitive Security Group Membership Modification
        # --------------------------------------------------

        elif event_id in {
            4728,
            4732,
        }:

            # Windows may generate group membership events
            # during normal account-management operations.
            #
            # Do not create a high-severity incident for every
            # group change. Alert only when the destination
            # group is security-sensitive.

            group_name = _clean(
                event.get("target_user")
                or event.get("target_username")
                or event.get("group_name")
                or event.get("TargetUserName")
            )

            member_name = _clean(
                event.get("member_name")
                or event.get("MemberName")
                or event.get("subject_user")
                or event.get("username")
            )

            sensitive_groups = {
                "administrators",
                "domain admins",
                "enterprise admins",
                "schema admins",
                "account operators",
                "backup operators",
                "server operators",
                "print operators",
                "remote desktop users",
                "hyper-v administrators",
            }

            normalized_group = (
                group_name
                .strip()
                .lower()
                if group_name
                else ""
            )

            if normalized_group in sensitive_groups:

                detections.append(

                    _build_detection(

                        detection_type=(
                            DETECTION_GROUP_MODIFICATION
                        ),

                        detection_category=(
                            "privilege_escalation"
                        ),

                        description=(
                            "A member was added to a "
                            "security-sensitive Windows group."
                        ),

                        source_event=event,

                        evidence=[
                            (
                                f"Windows Event ID "
                                f"{event_id} recorded a "
                                f"security group membership change."
                            ),
                            (
                                f"Sensitive group: "
                                f"{group_name}"
                            ),
                            (
                                f"Member: "
                                f"{member_name}"
                            ),
                        ],

                        confidence="high",
                    )
                )
        # --------------------------------------------------
        # Scheduled Task
        # --------------------------------------------------

        elif event_id == 4698:

            detections.append(

                _build_detection(

                    detection_type=(
                        DETECTION_SCHEDULED_TASK
                    ),

                    detection_category=(
                        "scheduled_task"
                    ),

                    description=(
                        "A Windows scheduled task "
                        "was created."
                    ),

                    source_event=event,

                    evidence=[

                        (
                            "Windows Event ID 4698 "
                            "was recorded."
                        ),

                        (
                            "Task name: "
                            f"{event.get('task_name')}"
                        ),
                    ],

                    confidence="high",
                )
            )

        # --------------------------------------------------
        # Audit Log Cleared
        # --------------------------------------------------

        elif event_id == 1102:

            detections.append(

                _build_detection(

                    detection_type=(
                        DETECTION_AUDIT_LOG_CLEARED
                    ),

                    detection_category=(
                        "defense_evasion"
                    ),

                    description=(
                        "The Windows Security audit "
                        "log was cleared."
                    ),

                    source_event=event,

                    evidence=[

                        (
                            "Windows Event ID 1102 "
                            "was recorded."
                        ),
                    ],

                    confidence="high",
                )
            )

        # --------------------------------------------------
        # IMPORTANT:
        #
        # 4672 is NOT automatically detected as privilege
        # escalation.
        #
        # 4798 is NOT automatically detected as account
        # discovery.
        #
        # Both are common/noisy events and require stronger
        # context before becoming incidents.
        # --------------------------------------------------

        return detections


    # ======================================================
    # Failed Login Detection
    # ======================================================

    def _detect_multiple_failed_logins(
        self,
        correlation: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert repeated failed-login correlation into a
        context-aware detection.

        Local:
            Repeated Local Authentication Failures

        Remote:
            Potential Brute Force
        """

        source_ip = _clean(

            correlation.get(
                "source_ip"
            )
        )

        authentication_scope = _clean(

            correlation.get(
                "authentication_scope"
            )
        )

        event_count = _safe_int(

            correlation.get(
                "event_count"
            )
        )

        observed_window = correlation.get(
            "observed_window_seconds"
        )

        evidence = [

            (
                f"{event_count} failed authentication "
                "events were correlated."
            ),

            (
                "Windows Event ID 4625 "
                "triggered the correlation."
            ),

            (
                "Observed time window: "
                f"{observed_window} seconds."
            ),

        ]

        if source_ip is not None:

            evidence.append(

                f"Source IP: {source_ip}"
            )

        # --------------------------------------------------
        # Local authentication
        # --------------------------------------------------

        if (

            authentication_scope == "local"

            or _is_loopback(
                source_ip
            )

        ):

            return _build_detection(

                detection_type=(
                    DETECTION_REPEATED_LOCAL_FAILURES
                ),

                detection_category=(
                    "authentication"
                ),

                description=(

                    "Multiple failed local authentication "
                    "attempts occurred within a short "
                    "time window."
                ),

                correlation=correlation,

                evidence=evidence,

                confidence="high",
            )

        # --------------------------------------------------
        # Remote authentication
        # --------------------------------------------------

        if (

            authentication_scope == "remote"

            and source_ip is not None

        ):

            return _build_detection(

                detection_type=(
                    DETECTION_POTENTIAL_BRUTE_FORCE
                ),

                detection_category=(
                    "credential_access"
                ),

                description=(

                    "Multiple failed remote authentication "
                    "attempts from the same source were "
                    "observed within a short time window."
                ),

                correlation=correlation,

                evidence=evidence,

                confidence="high",
            )

        # --------------------------------------------------
        # Unknown context
        # --------------------------------------------------

        return _build_detection(

            detection_type=(
                "Multiple Failed Authentication Attempts"
            ),

            detection_category=(
                "authentication"
            ),

            description=(

                "Multiple failed authentication attempts "
                "were observed within a short time window."
            ),

            correlation=correlation,

            evidence=evidence,

            confidence="medium",
        )


    # ======================================================
    # Suspicious PowerShell
    # ======================================================

    def _detect_suspicious_powershell(
        self,
        event: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Inspect PowerShell script content for suspicious
        indicators.

        A normal 4104 event alone does NOT automatically
        create a detection.
        """

        content_parts = [

            _clean(
                event.get(
                    "script_block_text"
                )
            ),

            _clean(
                event.get(
                    "command_line"
                )
            ),

        ]

        content = " ".join(

            part

            for part in content_parts

            if part is not None
        )

        if not content:

            return None

        content_lower = content.lower()

        matches: List[str] = []

        for indicator, description in (
            POWERSHELL_INDICATORS.items()
        ):

            if indicator in content_lower:

                matches.append(
                    description
                )

        if not matches:

            return None

        return _build_detection(

            detection_type=(
                DETECTION_SUSPICIOUS_POWERSHELL
            ),

            detection_category=(
                "execution"
            ),

            description=(

                "PowerShell activity contained one or more "
                "security-relevant execution indicators."
            ),

            source_event=event,

            evidence=matches,

            confidence=(
                "high"
                if len(matches) >= 2
                else "medium"
            ),
        )


    # ======================================================
    # Suspicious Command
    # ======================================================

    def _detect_suspicious_command(
        self,
        event: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Inspect Event ID 4688 process creation events.

        Detection requires command-line/process evidence.
        """

        command_line = _clean(

            event.get(
                "command_line"
            )
        )

        process_name = _clean(

            event.get(
                "process_name"
            )
        )

        if (

            command_line is None

            and process_name is None

        ):

            return None

        searchable = " ".join(

            value

            for value in [

                process_name,

                command_line,

            ]

            if value is not None
        )

        matches: List[str] = []

        for pattern, description in (
            SUSPICIOUS_COMMAND_PATTERNS
        ):

            if pattern.search(
                searchable
            ):

                matches.append(
                    description
                )

        if not matches:

            return None

        process_basename = _basename(
            process_name
        )

        evidence = list(
            matches
        )

        if process_basename is not None:

            evidence.append(

                f"Process: {process_basename}"
            )

        if command_line is not None:

            evidence.append(

                f"Command line: {command_line}"
            )

        return _build_detection(

            detection_type=(
                DETECTION_SUSPICIOUS_COMMAND
            ),

            detection_category=(
                "execution"
            ),

            description=(

                "A process creation event contained a "
                "security-relevant command pattern."
            ),

            source_event=event,

            evidence=evidence,

            confidence="high",
        )


# ==========================================================
# Development Output
# ==========================================================

def print_detection(
    detection: Dict[str, Any],
) -> None:
    """
    Print one detection during development.
    """

    print()

    print(
        "=" * 76
    )

    print(
        "SECURITY DETECTION"
    )

    print(
        "=" * 76
    )

    fields = [

        "detection_type",
        "detection_category",
        "description",
        "confidence",

        "event_id",

        "event_count",
        "threshold",

        "first_seen",
        "last_seen",

        "source_ip",
        "authentication_scope",

        "username",

        "hostname",
        "host_ip",

        "logon_type",
        "logon_type_name",

        "process_name",
        "command_line",

        "record_ids",
    ]

    for field in fields:

        value = detection.get(
            field
        )

        if value is not None:

            print(
                f"{field:<28}: {value}"
            )

    evidence = detection.get(
        "evidence",
        []
    )

    if evidence:

        print()

        print(
            "Evidence:"
        )

        for item in evidence:

            print(
                f"  - {item}"
            )

    print(
        "=" * 76
    )


# ==========================================================
# Standalone Test
# ==========================================================

def _run_test() -> None:
    """
    Test detection logic without requiring live Windows logs.
    """

    engine = DetectionEngine()

    print()
    print(
        "Detection Engine Test"
    )
    print(
        "-" * 50
    )

    # ======================================================
    # Test 1
    # Local failed authentication correlation
    # ======================================================

    local_correlation = {

        "correlation_type":
            "multiple_failed_logins",

        "event_count":
            3,

        "threshold":
            3,

        "observed_window_seconds":
            4.946,

        "first_seen":
            "2026-07-20T18:43:46+00:00",

        "last_seen":
            "2026-07-20T18:43:51+00:00",

        "source_ip":
            "127.0.0.1",

        "authentication_scope":
            "local",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "record_ids":
            [
                1001,
                1002,
                1003,
            ],

        "latest_event": {

            "event_id":
                4625,

            "event_name":
                "Failed Logon",

            "record_id":
                1003,

            "timestamp":
                "2026-07-20T18:43:51+00:00",

            "source_ip":
                "127.0.0.1",

            "authentication_scope":
                "local",

            "hostname":
                "TEST-PC",

            "host_ip":
                "192.168.1.20",

            "logon_type":
                2,

            "logon_type_name":
                "Interactive",
        },
    }

    local_results = (
        engine.process_correlation(
            local_correlation
        )
    )

    print()

    print(
        "Test 1 - Local Failed Logins:"
    )

    print(
        f"Detections: {len(local_results)}"
    )

    for result in local_results:

        print_detection(
            result
        )

    # ======================================================
    # Test 2
    # Remote failed authentication correlation
    # ======================================================

    remote_correlation = {

        **local_correlation,

        "source_ip":
            "192.168.1.50",

        "authentication_scope":
            "remote",

        "latest_event": {

            **local_correlation[
                "latest_event"
            ],

            "source_ip":
                "192.168.1.50",

            "authentication_scope":
                "remote",

            "logon_type":
                10,

            "logon_type_name":
                "Remote Interactive",
        },
    }

    remote_results = (
        engine.process_correlation(
            remote_correlation
        )
    )

    print()

    print(
        "Test 2 - Remote Failed Logins:"
    )

    print(
        f"Detections: {len(remote_results)}"
    )

    for result in remote_results:

        print_detection(
            result
        )

    # ======================================================
    # Test 3
    # Normal PowerShell - should NOT detect
    # ======================================================

    normal_powershell = {

        "event_id":
            4104,

        "event_name":
            "PowerShell Script Block Logging",

        "script_block_text":
            "Get-Process",

        "hostname":
            "TEST-PC",
    }

    normal_ps_results = (
        engine.process_event(
            normal_powershell
        )
    )

    print()

    print(
        "Test 3 - Normal PowerShell:"
    )

    print(
        f"Detections: {len(normal_ps_results)}"
    )

    # ======================================================
    # Test 4
    # Suspicious PowerShell
    # ======================================================

    suspicious_powershell = {

        "event_id":
            4104,

        "event_name":
            "PowerShell Script Block Logging",

        "record_id":
            2001,

        "timestamp":
            "2026-07-20T19:00:00+00:00",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "script_block_text":
            (
                "powershell -ExecutionPolicy Bypass "
                "-EncodedCommand AAAA"
            ),
    }

    suspicious_ps_results = (
        engine.process_event(
            suspicious_powershell
        )
    )

    print()

    print(
        "Test 4 - Suspicious PowerShell:"
    )

    print(
        f"Detections: {len(suspicious_ps_results)}"
    )

    for result in suspicious_ps_results:

        print_detection(
            result
        )

    # ======================================================
    # Test 5
    # 4672 should NOT automatically detect
    # ======================================================

    privilege_event = {

        "event_id":
            4672,

        "event_name":
            "Special Privileges Assigned to New Logon",

        "username":
            "Administrator",

        "hostname":
            "TEST-PC",
    }

    privilege_results = (
        engine.process_event(
            privilege_event
        )
    )

    print()

    print(
        "Test 5 - Normal 4672:"
    )

    print(
        f"Detections: {len(privilege_results)}"
    )

    # ======================================================
    # Test 6
    # 4798 should NOT automatically detect
    # ======================================================

    discovery_event = {

        "event_id":
            4798,

        "event_name":
            "Local Group Membership Enumerated",

        "hostname":
            "TEST-PC",
    }

    discovery_results = (
        engine.process_event(
            discovery_event
        )
    )

    print()

    print(
        "Test 6 - Standalone 4798:"
    )

    print(
        f"Detections: {len(discovery_results)}"
    )


if __name__ == "__main__":

    _run_test()