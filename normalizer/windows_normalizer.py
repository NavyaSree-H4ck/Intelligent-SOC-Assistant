"""
windows_normalizer.py

Purpose
-------
Normalizes parsed Windows Event Log data into one consistent
schema for the Intelligent SOC Assistant.

Pipeline
--------
Windows Event Logs
        ↓
windows_event_monitor.py
        ↓
parser/parser.py
        ↓
windows_normalizer.py
        ↓
correlation_engine.py
        ↓
detection_engine.py

Responsibilities
----------------
1. Accept parsed Windows events.
2. Convert different Event IDs into one standard schema.
3. Add monitored-host information.
4. Categorize Windows events.
5. Provide human-readable event names.
6. Distinguish local and remote network addresses.
7. Preserve original parsed data and raw XML.

Important
---------
This module DOES NOT:

- Detect brute force attacks
- Count failed logins
- Correlate events
- Assign severity
- Map MITRE ATT&CK
- Create incidents
- Invent attacker IP addresses

Missing evidence remains None.
"""

from __future__ import annotations

import getpass
import platform
import socket
from functools import lru_cache
from typing import Any, Dict, Optional


# ==========================================================
# Windows Event Names
# ==========================================================

EVENT_NAMES = {

    # Authentication
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon Using Explicit Credentials",

    # Privileges
    4672: "Special Privileges Assigned to New Logon",

    # Process
    4688: "New Process Created",

    # Service
    4697: "Service Installed",

    # Scheduled Task
    4698: "Scheduled Task Created",

    # Account Management
    4720: "User Account Created",
    4726: "User Account Deleted",

    # Group Management
    4728: "Member Added to Global Security Group",
    4732: "Member Added to Local Security Group",

    # Discovery
    4798: "Local Group Membership Enumerated",

    # Audit
    1102: "Audit Log Cleared",

    # Network
    5156: "Windows Filtering Platform Connection Allowed",

    # PowerShell
    4103: "PowerShell Module Logging",
    4104: "PowerShell Script Block Logging",
}


# ==========================================================
# Event Categories
# ==========================================================

EVENT_CATEGORIES = {

    4624: "authentication",
    4625: "authentication",
    4648: "authentication",

    4672: "privilege",

    4688: "process",

    4697: "service",
    4698: "scheduled_task",

    4720: "account_management",
    4726: "account_management",

    4728: "group_management",
    4732: "group_management",

    4798: "discovery",

    1102: "audit",

    5156: "network",

    4103: "powershell",
    4104: "powershell",
}


# ==========================================================
# Logon Type Names
# ==========================================================

LOGON_TYPE_NAMES = {

    0: "System",

    2: "Interactive",

    3: "Network",

    4: "Batch",

    5: "Service",

    7: "Unlock",

    8: "Network Cleartext",

    9: "New Credentials",

    10: "Remote Interactive",

    11: "Cached Interactive",

    12: "Cached Remote Interactive",

    13: "Cached Unlock",
}


# ==========================================================
# Utility Functions
# ==========================================================

def _clean(
    value: Any
) -> Optional[str]:
    """
    Convert a value into a clean string.

    Windows placeholders are converted to None.
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
        "n/a",
        "none",
        "null",

    }:

        return None

    return value


def _safe_int(
    value: Any
) -> Optional[int]:
    """
    Convert decimal or hexadecimal values safely to integers.
    """

    value = _clean(
        value
    )

    if value is None:

        return None

    try:

        if value.lower().startswith(
            "0x"
        ):

            return int(
                value,
                16
            )

        return int(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None


def _normalize_ip(
    value: Any
) -> Optional[str]:
    """
    Normalize an IP address without inventing information.

    IPv4-mapped IPv6:

        ::ffff:192.168.1.20

    becomes:

        192.168.1.20

    Loopback values are preserved because they are legitimate
    evidence from the Windows event.
    """

    value = _clean(
        value
    )

    if value is None:

        return None

    if value.lower().startswith(
        "::ffff:"
    ):

        mapped = value[7:]

        if mapped:

            return mapped

    return value


def _is_loopback(
    ip_address: Optional[str]
) -> bool:
    """
    Return True when an address represents localhost.
    """

    if ip_address is None:

        return False

    return ip_address.lower() in {

        "127.0.0.1",
        "::1",
        "localhost",

    }


# ==========================================================
# Host Information
# ==========================================================

@lru_cache(
    maxsize=1
)
def get_host_information() -> Dict[str, Optional[str]]:
    """
    Return information about the monitored Windows host.

    The result is cached because hostname/IP/OS information
    does not need to be recalculated for every event.

    Important
    ---------
    host_ip represents the monitored machine.

    It must NOT be confused with source_ip.

    source_ip:
        Address recorded in the Windows security event.

    host_ip:
        Address of the computer running the SOC collector.
    """

    hostname = socket.gethostname()

    fqdn = None

    try:

        fqdn = socket.getfqdn()

    except Exception:

        fqdn = hostname

    host_ip = None

    # ------------------------------------------------------
    # Determine a useful local IPv4 address.
    #
    # UDP connect does not actually send application data.
    # It asks the OS which local interface would be used.
    # ------------------------------------------------------

    udp_socket = None

    try:

        udp_socket = socket.socket(

            socket.AF_INET,

            socket.SOCK_DGRAM
        )

        udp_socket.connect(

            (
                "8.8.8.8",
                80
            )

        )

        host_ip = udp_socket.getsockname()[0]

    except OSError:

        try:

            host_ip = socket.gethostbyname(
                hostname
            )

        except OSError:

            host_ip = None

    finally:

        if udp_socket is not None:

            try:

                udp_socket.close()

            except OSError:

                pass

    # ------------------------------------------------------
    # Do not use loopback as the preferred victim/host IP
    # when a meaningful address cannot be determined.
    # ------------------------------------------------------

    if _is_loopback(
        host_ip
    ):

        host_ip = None

    try:

        logged_in_user = getpass.getuser()

    except Exception:

        logged_in_user = None

    return {

        "hostname":
            _clean(
                hostname
            ),

        "fqdn":
            _clean(
                fqdn
            ),

        "host_ip":
            _normalize_ip(
                host_ip
            ),

        "os":
            _clean(
                platform.system()
            ),

        "os_release":
            _clean(
                platform.release()
            ),

        "os_version":
            _clean(
                platform.version()
            ),

        "architecture":
            _clean(
                platform.machine()
            ),

        "logged_in_user":
            _clean(
                logged_in_user
            ),
    }


# ==========================================================
# Event Name
# ==========================================================

def get_event_name(
    event_id: Optional[int]
) -> str:
    """
    Return a human-readable Windows Event name.
    """

    if event_id is None:

        return "Unknown Windows Event"

    return EVENT_NAMES.get(

        event_id,

        f"Windows Event {event_id}"
    )


# ==========================================================
# Event Category
# ==========================================================

def get_event_category(
    event_id: Optional[int]
) -> str:
    """
    Return the general security category of an event.
    """

    if event_id is None:

        return "unknown"

    return EVENT_CATEGORIES.get(

        event_id,

        "other"
    )


# ==========================================================
# Logon Type
# ==========================================================

def get_logon_type_name(
    logon_type: Any
) -> Optional[str]:
    """
    Convert Windows LogonType into a readable description.

    Example:

        2  -> Interactive
        3  -> Network
        7  -> Unlock
        10 -> Remote Interactive
    """

    logon_type_int = _safe_int(
        logon_type
    )

    if logon_type_int is None:

        return None

    return LOGON_TYPE_NAMES.get(

        logon_type_int,

        f"Logon Type {logon_type_int}"
    )


# ==========================================================
# Authentication Scope
# ==========================================================

def determine_authentication_scope(
    source_ip: Optional[str],
    logon_type: Optional[int],
) -> str:
    """
    Classify authentication context.

    Returns one of:

        local
        remote
        unknown

    This is classification only.

    It does NOT classify the event as malicious.
    """

    if _is_loopback(
        source_ip
    ):

        return "local"

    if source_ip is not None:

        return "remote"

    if logon_type in {

        2,   # Interactive
        7,   # Unlock
        11,  # Cached Interactive
        13,  # Cached Unlock

    }:

        return "local"

    if logon_type in {

        3,   # Network
        8,   # Network Cleartext
        10,  # Remote Interactive

    }:

        return "remote"

    return "unknown"


# ==========================================================
# Event-Specific Username Selection
# ==========================================================

def _select_username(
    parsed_event: Dict[str, Any],
    event_id: Optional[int],
) -> Optional[str]:
    """
    Select the most appropriate username for the event.

    Authentication events prefer the target account.

    We intentionally do NOT automatically substitute
    SubjectUserName for a missing authentication target,
    because this could incorrectly label machine/service
    accounts such as NICK$ as the attempted login account.
    """

    target_user = _clean(

        parsed_event.get(
            "target_user"
        )
    )

    subject_user = _clean(

        parsed_event.get(
            "subject_user"
        )
    )

    parsed_username = _clean(

        parsed_event.get(
            "username"
        )
    )

    if event_id in {

        4624,
        4625,
        4648,

    }:

        return target_user or parsed_username

    return (

        parsed_username
        or target_user
        or subject_user

    )


# ==========================================================
# Event-Specific Domain Selection
# ==========================================================

def _select_domain(
    parsed_event: Dict[str, Any],
    event_id: Optional[int],
) -> Optional[str]:
    """
    Select the most appropriate domain for the event.
    """

    target_domain = _clean(

        parsed_event.get(
            "target_domain"
        )
    )

    subject_domain = _clean(

        parsed_event.get(
            "subject_domain"
        )
    )

    parsed_domain = _clean(

        parsed_event.get(
            "domain"
        )
    )

    if event_id in {

        4624,
        4625,
        4648,

    }:

        return target_domain or parsed_domain

    return (

        parsed_domain
        or target_domain
        or subject_domain

    )


# ==========================================================
# Main Normalizer
# ==========================================================

def normalize_windows_event(
    parsed_event: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Normalize one parsed Windows event.

    Parameters
    ----------
    parsed_event:

        Dictionary returned by parser.parse_event().

    Returns
    -------
    dict | None

        Standard normalized Windows event.

        Returns None when input is invalid.
    """

    if not isinstance(
        parsed_event,
        dict
    ):

        return None

    event_id = _safe_int(

        parsed_event.get(
            "event_id"
        )
    )

    record_id = _safe_int(

        parsed_event.get(
            "record_id"
        )
    )

    logon_type = _safe_int(

        parsed_event.get(
            "logon_type"
        )
    )

    source_ip = _normalize_ip(

        parsed_event.get(
            "source_ip"
        )
    )

    destination_ip = _normalize_ip(

        parsed_event.get(
            "destination_ip"
        )
    )

    host = get_host_information()

    username = _select_username(

        parsed_event,

        event_id
    )

    domain = _select_domain(

        parsed_event,

        event_id
    )

    authentication_scope = (
        determine_authentication_scope(

            source_ip,

            logon_type
        )
    )

    # ======================================================
    # Build Standard Event
    # ======================================================

    normalized_event: Dict[
        str,
        Any
    ] = {

        # ==================================================
        # Schema
        # ==================================================

        "schema_version":
            "1.0",

        "event_source":
            "windows",

        # ==================================================
        # Event Identity
        # ==================================================

        "event_id":
            event_id,

        "event_name":
            get_event_name(
                event_id
            ),

        "event_category":
            get_event_category(
                event_id
            ),

        "record_id":
            record_id,

        # ==================================================
        # Time
        # ==================================================

        "timestamp":
            _clean(
                parsed_event.get(
                    "timestamp"
                )
            ),

        "collected_at":
            _clean(
                parsed_event.get(
                    "collected_at"
                )
            ),

        # ==================================================
        # Windows Metadata
        # ==================================================

        "provider":
            _clean(
                parsed_event.get(
                    "provider"
                )
            ),

        "channel":
            _clean(
                parsed_event.get(
                    "channel"
                )
            ),

        "computer":
            _clean(
                parsed_event.get(
                    "computer"
                )
            ),

        "level":
            parsed_event.get(
                "level"
            ),

        "task":
            parsed_event.get(
                "task"
            ),

        "opcode":
            parsed_event.get(
                "opcode"
            ),

        "keywords":
            _clean(
                parsed_event.get(
                    "keywords"
                )
            ),

        # ==================================================
        # Monitored Host / Victim
        # ==================================================

        "hostname":
            host.get(
                "hostname"
            ),

        "fqdn":
            host.get(
                "fqdn"
            ),

        "host_ip":
            host.get(
                "host_ip"
            ),

        "operating_system":
            host.get(
                "os"
            ),

        "os_release":
            host.get(
                "os_release"
            ),

        "os_version":
            host.get(
                "os_version"
            ),

        "architecture":
            host.get(
                "architecture"
            ),

        "logged_in_user":
            host.get(
                "logged_in_user"
            ),

        # ==================================================
        # Primary User Context
        # ==================================================

        "username":
            username,

        "domain":
            domain,

        "user_sid":
            _clean(
                parsed_event.get(
                    "user_sid"
                )
            ),

        # ==================================================
        # Subject
        # ==================================================

        "subject_user":
            _clean(
                parsed_event.get(
                    "subject_user"
                )
            ),

        "subject_domain":
            _clean(
                parsed_event.get(
                    "subject_domain"
                )
            ),

        "subject_sid":
            _clean(
                parsed_event.get(
                    "subject_sid"
                )
            ),

        "subject_logon_id":
            _clean(
                parsed_event.get(
                    "subject_logon_id"
                )
            ),

        # ==================================================
        # Target
        # ==================================================

        "target_user":
            _clean(
                parsed_event.get(
                    "target_user"
                )
            ),

        "target_domain":
            _clean(
                parsed_event.get(
                    "target_domain"
                )
            ),

        "target_sid":
            _clean(
                parsed_event.get(
                    "target_sid"
                )
            ),

        "target_logon_id":
            _clean(
                parsed_event.get(
                    "target_logon_id"
                )
            ),

        # ==================================================
        # Authentication
        # ==================================================

        "logon_type":
            logon_type,

        "logon_type_name":
            get_logon_type_name(
                logon_type
            ),

        "authentication_scope":
            authentication_scope,

        "logon_process":
            _clean(
                parsed_event.get(
                    "logon_process"
                )
            ),

        "authentication_package":
            _clean(
                parsed_event.get(
                    "authentication_package"
                )
            ),

        "failure_reason":
            _clean(
                parsed_event.get(
                    "failure_reason"
                )
            ),

        "status":
            _clean(
                parsed_event.get(
                    "status"
                )
            ),

        "sub_status":
            _clean(
                parsed_event.get(
                    "sub_status"
                )
            ),

        # ==================================================
        # Network
        # ==================================================

        "source_ip":
            source_ip,

        "source_port":
            _safe_int(
                parsed_event.get(
                    "source_port"
                )
            ),

        "destination_ip":
            destination_ip,

        "destination_port":
            _safe_int(
                parsed_event.get(
                    "destination_port"
                )
            ),

        "workstation_name":
            _clean(
                parsed_event.get(
                    "workstation_name"
                )
            ),

        # ==================================================
        # Process
        # ==================================================

        "process_name":
            _clean(
                parsed_event.get(
                    "process_name"
                )
            ),

        "new_process_name":
            _clean(
                parsed_event.get(
                    "new_process_name"
                )
            ),

        "parent_process_name":
            _clean(
                parsed_event.get(
                    "parent_process_name"
                )
            ),

        "process_id":
            _safe_int(
                parsed_event.get(
                    "process_id"
                )
            ),

        "parent_process_id":
            _safe_int(
                parsed_event.get(
                    "parent_process_id"
                )
            ),

        "command_line":
            _clean(
                parsed_event.get(
                    "command_line"
                )
            ),

        # ==================================================
        # PowerShell
        # ==================================================

        "script_block_text":
            _clean(
                parsed_event.get(
                    "script_block_text"
                )
            ),

        "script_block_id":
            _clean(
                parsed_event.get(
                    "script_block_id"
                )
            ),

        "script_path":
            _clean(
                parsed_event.get(
                    "script_path"
                )
            ),

        # ==================================================
        # Account / Group
        # ==================================================

        "member_name":
            _clean(
                parsed_event.get(
                    "member_name"
                )
            ),

        "member_sid":
            _clean(
                parsed_event.get(
                    "member_sid"
                )
            ),

        "group_name":
            _clean(
                parsed_event.get(
                    "group_name"
                )
            ),

        "group_domain":
            _clean(
                parsed_event.get(
                    "group_domain"
                )
            ),

        # ==================================================
        # Other Security Data
        # ==================================================

        "privilege_list":
            _clean(
                parsed_event.get(
                    "privilege_list"
                )
            ),

        "service_name":
            _clean(
                parsed_event.get(
                    "service_name"
                )
            ),

        "service_file_name":
            _clean(
                parsed_event.get(
                    "service_file_name"
                )
            ),

        "task_name":
            _clean(
                parsed_event.get(
                    "task_name"
                )
            ),

        # ==================================================
        # Correlation Metadata
        #
        # These fields do NOT mean an attack was detected.
        # They provide consistent data for the future
        # correlation engine.
        # ==================================================

        "correlation_key":
            _build_correlation_key(

                event_id=event_id,

                username=username,

                source_ip=source_ip,

                hostname=host.get(
                    "hostname"
                ),
            ),

        # ==================================================
        # Original Evidence
        # ==================================================

        "event_data":
            parsed_event.get(
                "event_data",
                {}
            ),

        "user_data":
            parsed_event.get(
                "user_data",
                {}
            ),

        "raw_xml":
            parsed_event.get(
                "raw_xml"
            ),
    }

    return normalized_event


# ==========================================================
# Correlation Key
# ==========================================================

def _build_correlation_key(
    event_id: Optional[int],
    username: Optional[str],
    source_ip: Optional[str],
    hostname: Optional[str],
) -> str:
    """
    Build a stable helper key for future correlation.

    Example:

        4625|navya|192.168.1.50|NICK

    Missing values are represented as 'unknown'.

    This key does NOT itself detect an attack.
    """

    return "|".join(

        [

            str(
                event_id
                if event_id is not None
                else "unknown"
            ),

            (
                username
                or "unknown"
            ).lower(),

            (
                source_ip
                or "unknown"
            ).lower(),

            (
                hostname
                or "unknown"
            ).lower(),

        ]

    )


# ==========================================================
# Development Output
# ==========================================================

def print_normalized_event(
    event: Dict[str, Any]
) -> None:
    """
    Print selected normalized fields during development.

    This is temporary testing output.

    The final desktop application will send normalized events
    to the correlation/detection pipeline instead.
    """

    print()

    print(
        "=" * 68
    )

    print(
        "NORMALIZED WINDOWS EVENT"
    )

    print(
        "=" * 68
    )

    fields = [

        "event_id",
        "event_name",
        "event_category",

        "record_id",
        "timestamp",

        "hostname",
        "host_ip",

        "username",
        "domain",

        "subject_user",
        "target_user",

        "logon_type",
        "logon_type_name",
        "authentication_scope",

        "source_ip",
        "source_port",

        "destination_ip",
        "destination_port",

        "process_name",
        "parent_process_name",
        "command_line",

        "failure_reason",
        "status",
        "sub_status",

        "correlation_key",
    ]

    for field in fields:

        value = event.get(
            field
        )

        if value is not None:

            print(
                f"{field:<25}: {value}"
            )

    print(
        "=" * 68
    )


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    print(
        "windows_normalizer.py is ready."
    )

    print()

    print(
        "Monitored host information:"
    )

    host_information = (
        get_host_information()
    )

    for key, value in (
        host_information.items()
    ):

        print(
            f"{key:<20}: {value}"
        )