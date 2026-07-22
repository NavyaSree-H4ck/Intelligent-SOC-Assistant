"""
parser.py

Purpose
-------
Parses raw Windows Event XML collected by
live_monitor/windows_event_monitor.py.

Responsibilities
----------------
1. Parse Windows Event XML safely.
2. Extract System metadata.
3. Extract all EventData fields dynamically.
4. Extract UserData fields when present.
5. Create convenient normalized parser-level aliases.
6. Preserve the complete raw XML for investigation.

Important
---------
This module performs PARSING ONLY.

It does NOT:
- Detect attacks
- Correlate events
- Assign severity
- Map MITRE ATT&CK
- Generate recommendations
- Invent missing IP addresses or usernames

Missing values remain None.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET


# ==========================================================
# XML Namespace
# ==========================================================

WINDOWS_EVENT_NAMESPACE = (
    "http://schemas.microsoft.com/win/2004/08/events/event"
)

NS = {
    "e": WINDOWS_EVENT_NAMESPACE
}


# ==========================================================
# Utility Functions
# ==========================================================

def _clean_value(
    value: Any
) -> Optional[str]:
    """
    Clean a value extracted from Windows Event XML.

    Empty values and common Windows placeholders are returned
    as None.

    Important:
    A real value is never fabricated.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value in {
        "-",
        "N/A",
        "n/a",
        "NULL",
        "null"
    }:
        return None

    return value


def _safe_int(
    value: Any
) -> Optional[int]:
    """
    Convert a value to int safely.

    Supports normal decimal values and hexadecimal strings.
    """

    value = _clean_value(
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


def _strip_namespace(
    tag: str
) -> str:
    """
    Remove an XML namespace from a tag.

    Example:

    {namespace}EventData

    becomes:

    EventData
    """

    if "}" in tag:

        return tag.split(
            "}",
            1
        )[1]

    return tag


def _first_value(
    data: Dict[str, Any],
    *keys: str
) -> Optional[str]:
    """
    Return the first non-empty value from the requested keys.
    """

    for key in keys:

        value = _clean_value(
            data.get(
                key
            )
        )

        if value is not None:

            return value

    return None


def _normalize_ip(
    value: Any
) -> Optional[str]:
    """
    Clean an IP address extracted from Windows XML.

    Windows sometimes represents localhost IPv6 as ::1 or
    IPv4-mapped IPv6 addresses as ::ffff:x.x.x.x.

    We preserve real addresses while making IPv4-mapped
    addresses easier to use later.
    """

    value = _clean_value(
        value
    )

    if value is None:

        return None

    lower_value = value.lower()

    if lower_value.startswith(
        "::ffff:"
    ):

        mapped = value[7:]

        if mapped:

            return mapped

    return value


def _parse_timestamp(
    value: Any
) -> Optional[str]:
    """
    Parse the original Windows event timestamp.

    Windows commonly provides timestamps such as:

        2026-07-20T17:30:20.1234567Z

    The function returns an ISO-8601 timestamp string.

    If parsing cannot be completed, the original timestamp
    string is preserved rather than discarded.
    """

    value = _clean_value(
        value
    )

    if value is None:

        return None

    try:

        timestamp = value

        if timestamp.endswith(
            "Z"
        ):

            timestamp = (
                timestamp[:-1]
                + "+00:00"
            )

        # Python datetime supports up to 6 fractional digits.
        #
        # Windows can provide 7 fractional digits.
        if "." in timestamp:

            date_part, remainder = (
                timestamp.split(
                    ".",
                    1
                )
            )

            timezone_position = -1

            for marker in (
                "+",
                "-"
            ):

                position = remainder.find(
                    marker
                )

                if (
                    position != -1
                    and (
                        timezone_position == -1
                        or position < timezone_position
                    )
                ):

                    timezone_position = position

            if timezone_position != -1:

                fraction = remainder[
                    :timezone_position
                ]

                timezone_part = remainder[
                    timezone_position:
                ]

            else:

                fraction = remainder

                timezone_part = ""

            fraction = fraction[:6]

            timestamp = (
                f"{date_part}."
                f"{fraction}"
                f"{timezone_part}"
            )

        parsed = datetime.fromisoformat(
            timestamp
        )

        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.isoformat()

    except (
        TypeError,
        ValueError
    ):

        return value


# ==========================================================
# Parse EventData
# ==========================================================

def _parse_event_data(
    root: ET.Element
) -> Dict[str, Any]:
    """
    Extract all named fields from <EventData>.

    Example XML:

        <EventData>
            <Data Name="TargetUserName">user1</Data>
            <Data Name="IpAddress">192.168.1.10</Data>
        </EventData>

    Output:

        {
            "TargetUserName": "user1",
            "IpAddress": "192.168.1.10"
        }

    Duplicate field names are preserved as lists.
    """

    result: Dict[
        str,
        Any
    ] = {}

    event_data = root.find(
        "e:EventData",
        NS
    )

    if event_data is None:

        return result

    unnamed_counter = 0

    for data_element in list(
        event_data
    ):

        if _strip_namespace(
            data_element.tag
        ) != "Data":

            continue

        name = _clean_value(
            data_element.attrib.get(
                "Name"
            )
        )

        if name is None:

            name = (
                f"UnnamedData"
                f"{unnamed_counter}"
            )

            unnamed_counter += 1

        value = _clean_value(
            data_element.text
        )

        if name not in result:

            result[
                name
            ] = value

        else:

            existing = result[
                name
            ]

            if isinstance(
                existing,
                list
            ):

                existing.append(
                    value
                )

            else:

                result[
                    name
                ] = [
                    existing,
                    value
                ]

    return result


# ==========================================================
# Parse UserData
# ==========================================================

def _parse_user_data(
    root: ET.Element
) -> Dict[str, Any]:
    """
    Extract fields from <UserData> recursively.

    Some Windows Event providers use UserData instead of
    EventData.
    """

    result: Dict[
        str,
        Any
    ] = {}

    user_data = root.find(
        "e:UserData",
        NS
    )

    if user_data is None:

        return result

    for element in user_data.iter():

        if element is user_data:

            continue

        if len(
            list(element)
        ) > 0:

            continue

        key = _strip_namespace(
            element.tag
        )

        value = _clean_value(
            element.text
        )

        if key not in result:

            result[
                key
            ] = value

        else:

            existing = result[
                key
            ]

            if isinstance(
                existing,
                list
            ):

                existing.append(
                    value
                )

            else:

                result[
                    key
                ] = [
                    existing,
                    value
                ]

    return result


# ==========================================================
# Parse System Metadata
# ==========================================================

def _parse_system(
    root: ET.Element
) -> Dict[str, Any]:
    """
    Extract fields from the Windows <System> section.
    """

    system = root.find(
        "e:System",
        NS
    )

    if system is None:

        return {}

    # ------------------------------------------------------
    # Provider
    # ------------------------------------------------------

    provider_element = system.find(
        "e:Provider",
        NS
    )

    provider = None

    provider_guid = None

    if provider_element is not None:

        provider = _clean_value(
            provider_element.attrib.get(
                "Name"
            )
        )

        provider_guid = _clean_value(
            provider_element.attrib.get(
                "Guid"
            )
        )

    # ------------------------------------------------------
    # Event ID
    # ------------------------------------------------------

    event_id_element = system.find(
        "e:EventID",
        NS
    )

    event_id = None

    event_qualifiers = None

    if event_id_element is not None:

        event_id = _safe_int(
            event_id_element.text
        )

        event_qualifiers = _clean_value(
            event_id_element.attrib.get(
                "Qualifiers"
            )
        )

    # ------------------------------------------------------
    # TimeCreated
    # ------------------------------------------------------

    time_element = system.find(
        "e:TimeCreated",
        NS
    )

    timestamp = None

    if time_element is not None:

        timestamp = _parse_timestamp(
            time_element.attrib.get(
                "SystemTime"
            )
        )

    # ------------------------------------------------------
    # Correlation
    # ------------------------------------------------------

    correlation_element = system.find(
        "e:Correlation",
        NS
    )

    activity_id = None

    related_activity_id = None

    if correlation_element is not None:

        activity_id = _clean_value(
            correlation_element.attrib.get(
                "ActivityID"
            )
        )

        related_activity_id = _clean_value(
            correlation_element.attrib.get(
                "RelatedActivityID"
            )
        )

    # ------------------------------------------------------
    # Security
    # ------------------------------------------------------

    security_element = system.find(
        "e:Security",
        NS
    )

    security_user_id = None

    if security_element is not None:

        security_user_id = _clean_value(
            security_element.attrib.get(
                "UserID"
            )
        )

    # ------------------------------------------------------
    # Standard elements
    # ------------------------------------------------------

    def get_text(
        tag: str
    ) -> Optional[str]:

        element = system.find(
            f"e:{tag}",
            NS
        )

        if element is None:

            return None

        return _clean_value(
            element.text
        )

    return {

        "provider":
            provider,

        "provider_guid":
            provider_guid,

        "event_id":
            event_id,

        "event_qualifiers":
            event_qualifiers,

        "version":
            _safe_int(
                get_text(
                    "Version"
                )
            ),

        "level":
            _safe_int(
                get_text(
                    "Level"
                )
            ),

        "task":
            _safe_int(
                get_text(
                    "Task"
                )
            ),

        "opcode":
            _safe_int(
                get_text(
                    "Opcode"
                )
            ),

        "keywords":
            get_text(
                "Keywords"
            ),

        "timestamp":
            timestamp,

        "event_record_id":
            _safe_int(
                get_text(
                    "EventRecordID"
                )
            ),

        "channel":
            get_text(
                "Channel"
            ),

        "computer":
            get_text(
                "Computer"
            ),

        "activity_id":
            activity_id,

        "related_activity_id":
            related_activity_id,

        "security_user_id":
            security_user_id,
    }


# ==========================================================
# Main Parser
# ==========================================================

def parse_event(
    raw_event: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Parse one raw event produced by windows_event_monitor.py.

    Parameters
    ----------
    raw_event:

        Expected structure:

        {
            "event_id": 4625,
            "record_id": 12345,
            "channel": "Security",
            "collected_at": "...",
            "xml": "<Event>...</Event>"
        }

    Returns
    -------
    dict | None

        Parsed Windows event dictionary.

        Returns None when XML is invalid or unavailable.
    """

    if not isinstance(
        raw_event,
        dict
    ):

        return None

    xml = raw_event.get(
        "xml"
    )

    if not isinstance(
        xml,
        str
    ):

        return None

    if not xml.strip():

        return None

    try:

        root = ET.fromstring(
            xml
        )

    except ET.ParseError as error:

        print(
            "[PARSER ERROR] "
            f"Invalid Windows Event XML: {error}"
        )

        return None

    # ------------------------------------------------------
    # Parse sections
    # ------------------------------------------------------

    system = _parse_system(
        root
    )

    event_data = _parse_event_data(
        root
    )

    user_data = _parse_user_data(
        root
    )

    # Combine EventData and UserData for convenient lookup.
    #
    # EventData takes priority because Security events
    # commonly use named EventData fields.

    combined_data: Dict[
        str,
        Any
    ] = {}

    combined_data.update(
        user_data
    )

    combined_data.update(
        event_data
    )

    # ------------------------------------------------------
    # Event identity
    # ------------------------------------------------------

    event_id = (
        system.get(
            "event_id"
        )
        or _safe_int(
            raw_event.get(
                "event_id"
            )
        )
    )

    record_id = (
        system.get(
            "event_record_id"
        )
        or _safe_int(
            raw_event.get(
                "record_id"
            )
        )
    )

    channel = (
        system.get(
            "channel"
        )
        or _clean_value(
            raw_event.get(
                "channel"
            )
        )
    )

    # ------------------------------------------------------
    # User / Account fields
    # ------------------------------------------------------

    subject_user = _first_value(

        combined_data,

        "SubjectUserName"
    )

    target_user = _first_value(

        combined_data,

        "TargetUserName",

        "AccountName"
    )

# ------------------------------------------------------
# Primary Username
# ------------------------------------------------------
#
# Authentication events distinguish between:
#
# SubjectUserName
#     Account/process initiating the operation
#
# TargetUserName
#     Account being authenticated
#
# For authentication-related events, using SubjectUserName
# as a fallback can incorrectly identify machine/service
# accounts such as NICK$ as the attempted login account.

    if event_id in {
        4624,
        4625,
        4648,
    }:

        username = _first_value(

            combined_data,

            "TargetUserName",

            "AccountName"
        )

    else:
        

        username = _first_value(

        combined_data,

        "TargetUserName",

        "SubjectUserName",

        "AccountName",

        "UserName",

        "Username"
    )

    subject_domain = _first_value(

        combined_data,

        "SubjectDomainName"
    )

    target_domain = _first_value(

        combined_data,

        "TargetDomainName",

        "AccountDomain"
    )

    if event_id in {
    4624,
    4625,
    4648,
    }:
        

        domain = _first_value(

            combined_data,

            "TargetDomainName",

            "AccountDomain"
        )

    else:

        domain = _first_value(

        combined_data,

        "TargetDomainName",

        "SubjectDomainName",

        "AccountDomain",

        "DomainName"
    )

    subject_sid = _first_value(

        combined_data,

        "SubjectUserSid"
    )

    target_sid = _first_value(

        combined_data,

        "TargetUserSid",

        "AccountSid"
    )

    user_sid = _first_value(

        combined_data,

        "TargetUserSid",

        "SubjectUserSid",

        "AccountSid"
    )

    # ------------------------------------------------------
    # Network fields
    # ------------------------------------------------------

    source_ip = _normalize_ip(

        _first_value(

            combined_data,

            "IpAddress",

            "SourceAddress",

            "SourceIp",

            "SourceIP",

            "ClientAddress",

            "NetworkAddress"
        )
    )

    source_port = _first_value(

        combined_data,

        "IpPort",

        "SourcePort",

        "ClientPort"
    )

    destination_ip = _normalize_ip(

        _first_value(

            combined_data,

            "DestAddress",

            "DestinationAddress",

            "DestinationIp",

            "DestinationIP"
        )
    )

    destination_port = _first_value(

        combined_data,

        "DestPort",

        "DestinationPort"
    )

    workstation_name = _first_value(

        combined_data,

        "WorkstationName",

        "Workstation",

        "ClientName"
    )

    # ------------------------------------------------------
    # Process fields
    # ------------------------------------------------------

    new_process_name = _first_value(

        combined_data,

        "NewProcessName"
    )

    process_name = _first_value(

        combined_data,

        "NewProcessName",

        "ProcessName",

        "Application"
    )

    parent_process_name = _first_value(

        combined_data,

        "ParentProcessName",

        "CreatorProcessName"
    )

    process_id = _first_value(

        combined_data,

        "NewProcessId",

        "ProcessId",

        "ProcessID"
    )

    parent_process_id = _first_value(

        combined_data,

        "ProcessId",

        "CreatorProcessId",

        "ParentProcessId"
    )

    command_line = _first_value(

        combined_data,

        "ProcessCommandLine",

        "CommandLine"
    )

    # ------------------------------------------------------
    # PowerShell fields
    # ------------------------------------------------------

    script_block_text = _first_value(

        combined_data,

        "ScriptBlockText",

        "Payload"
    )

    script_block_id = _first_value(

        combined_data,

        "ScriptBlockId"
    )

    script_path = _first_value(

        combined_data,

        "Path"
    )

    # ------------------------------------------------------
    # Authentication fields
    # ------------------------------------------------------

    logon_type = _first_value(

        combined_data,

        "LogonType"
    )

    logon_process = _first_value(

        combined_data,

        "LogonProcessName"
    )

    authentication_package = _first_value(

        combined_data,

        "AuthenticationPackageName"
    )

    failure_reason = _first_value(

        combined_data,

        "FailureReason"
    )

    status = _first_value(

        combined_data,

        "Status"
    )

    sub_status = _first_value(

        combined_data,

        "SubStatus"
    )

    subject_logon_id = _first_value(

        combined_data,

        "SubjectLogonId"
    )

    target_logon_id = _first_value(

        combined_data,

        "TargetLogonId"
    )

    # ------------------------------------------------------
    # Account / Group fields
    # ------------------------------------------------------

    member_name = _first_value(

        combined_data,

        "MemberName"
    )

    member_sid = _first_value(

        combined_data,

        "MemberSid",

        "MemberId"
    )

    group_name = _first_value(

        combined_data,

        "GroupName"
    )

    group_domain = _first_value(

        combined_data,

        "TargetDomainName",

        "GroupDomain"
    )

    # ------------------------------------------------------
    # Privilege / Service / Task fields
    # ------------------------------------------------------

    privilege_list = _first_value(

        combined_data,

        "PrivilegeList"
    )

    service_name = _first_value(

        combined_data,

        "ServiceName"
    )

    service_file_name = _first_value(

        combined_data,

        "ServiceFileName",

        "ImagePath"
    )

    task_name = _first_value(

        combined_data,

        "TaskName"
    )

    # ------------------------------------------------------
    # Build Parsed Event
    # ------------------------------------------------------

    parsed_event: Dict[
        str,
        Any
    ] = {

        # ==================================================
        # Event Metadata
        # ==================================================

        "event_id":
            event_id,

        "record_id":
            record_id,

        "timestamp":
            system.get(
                "timestamp"
            ),

        "collected_at":
            _clean_value(
                raw_event.get(
                    "collected_at"
                )
            ),

        "provider":
            system.get(
                "provider"
            ),

        "provider_guid":
            system.get(
                "provider_guid"
            ),

        "channel":
            channel,

        "computer":
            system.get(
                "computer"
            ),

        "version":
            system.get(
                "version"
            ),

        "level":
            system.get(
                "level"
            ),

        "task":
            system.get(
                "task"
            ),

        "opcode":
            system.get(
                "opcode"
            ),

        "keywords":
            system.get(
                "keywords"
            ),

        "activity_id":
            system.get(
                "activity_id"
            ),

        "related_activity_id":
            system.get(
                "related_activity_id"
            ),

        "security_user_id":
            system.get(
                "security_user_id"
            ),

        # ==================================================
        # User / Account
        # ==================================================

        "username":
            username,

        "domain":
            domain,

        "user_sid":
            user_sid,

        "subject_user":
            subject_user,

        "subject_domain":
            subject_domain,

        "subject_sid":
            subject_sid,

        "target_user":
            target_user,

        "target_domain":
            target_domain,

        "target_sid":
            target_sid,

        "subject_logon_id":
            subject_logon_id,

        "target_logon_id":
            target_logon_id,

        # ==================================================
        # Authentication
        # ==================================================

        "logon_type":
            logon_type,

        "logon_process":
            logon_process,

        "authentication_package":
            authentication_package,

        "failure_reason":
            failure_reason,

        "status":
            status,

        "sub_status":
            sub_status,

        # ==================================================
        # Network
        # ==================================================

        "source_ip":
            source_ip,

        "source_port":
            source_port,

        "destination_ip":
            destination_ip,

        "destination_port":
            destination_port,

        "workstation_name":
            workstation_name,

        # ==================================================
        # Process
        # ==================================================

        "process_name":
            process_name,

        "new_process_name":
            new_process_name,

        "parent_process_name":
            parent_process_name,

        "process_id":
            process_id,

        "parent_process_id":
            parent_process_id,

        "command_line":
            command_line,

        # ==================================================
        # PowerShell
        # ==================================================

        "script_block_text":
            script_block_text,

        "script_block_id":
            script_block_id,

        "script_path":
            script_path,

        # ==================================================
        # Account / Group
        # ==================================================

        "member_name":
            member_name,

        "member_sid":
            member_sid,

        "group_name":
            group_name,

        "group_domain":
            group_domain,

        # ==================================================
        # Other Security Fields
        # ==================================================

        "privilege_list":
            privilege_list,

        "service_name":
            service_name,

        "service_file_name":
            service_file_name,

        "task_name":
            task_name,

        # ==================================================
        # Complete Parsed Data
        # ==================================================

        "event_data":
            event_data,

        "user_data":
            user_data,

        "raw_xml":
            xml,
    }

    return parsed_event


# ==========================================================
# Pretty Test Output
# ==========================================================

def print_parsed_event(
    event: Dict[str, Any]
) -> None:
    """
    Print important parsed fields for development testing.

    Empty fields are not printed.
    """

    print()

    print(
        "=" * 60
    )

    print(
        "PARSED WINDOWS EVENT"
    )

    print(
        "=" * 60
    )

    important_fields = [

        "event_id",
        "record_id",
        "timestamp",
        "collected_at",

        "provider",
        "channel",
        "computer",

        "username",
        "domain",

        "subject_user",
        "target_user",

        "logon_type",

        "source_ip",
        "source_port",

        "destination_ip",
        "destination_port",

        "workstation_name",

        "process_name",
        "parent_process_name",
        "command_line",

        "script_block_text",

        "failure_reason",
        "status",
        "sub_status",

        "privilege_list",

        "member_name",
        "group_name",
    ]

    for field in important_fields:

        value = event.get(
            field
        )

        if value is not None:

            print(
                f"{field:<24}: {value}"
            )

    print()

    print(
        "EventData fields:"
    )

    event_data = event.get(
        "event_data",
        {}
    )

    if event_data:

        for key, value in event_data.items():

            print(
                f"  {key:<30}: {value}"
            )

    else:

        print(
            "  None"
        )

    print(
        "=" * 60
    )


# ==========================================================
# Standalone Information
# ==========================================================

if __name__ == "__main__":

    print(
        "parser.py is ready."
    )

    print(
        "Run the Windows Event Monitor integration test "
        "to parse real Windows events."
    )