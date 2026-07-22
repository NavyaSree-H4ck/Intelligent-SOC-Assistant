"""
recommendation.py

Purpose
-------
SOC analyst recommendation engine for the
Intelligent SOC Assistant.

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
MITRE ATT&CK Mapper
        ↓
Recommendation Engine
        ↓
Database
        ↓
Reports
        ↓
Desktop Dashboard

Responsibilities
----------------
1. Receive an enriched security detection.
2. Generate practical SOC investigation actions.
3. Generate containment recommendations when appropriate.
4. Generate remediation and prevention guidance.
5. Set analyst response priority.
6. Preserve all existing detection information.

Important
---------
This module does NOT automatically:

- Block IP addresses
- Disable accounts
- Kill processes
- Delete files
- Modify firewall rules
- Perform remediation

It only recommends actions for an analyst.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional


# ==========================================================
# Priority Levels
# ==========================================================

PRIORITY_ROUTINE = "ROUTINE"

PRIORITY_STANDARD = "STANDARD"

PRIORITY_URGENT = "URGENT"

PRIORITY_IMMEDIATE = "IMMEDIATE"


# ==========================================================
# Helper Functions
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
    Safely convert a value to integer.
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


def _deduplicate(
    items: List[str],
) -> List[str]:
    """
    Remove duplicate recommendations while preserving order.
    """

    result: List[str] = []

    seen = set()

    for item in items:

        cleaned = _clean(
            item
        )

        if cleaned is None:
            continue

        key = cleaned.lower()

        if key in seen:
            continue

        seen.add(
            key
        )

        result.append(
            cleaned
        )

    return result


# ==========================================================
# Recommendation Engine
# ==========================================================

class RecommendationEngine:
    """
    Generate SOC analyst recommendations for detections.

    Usage
    -----

        engine = RecommendationEngine()

        enriched_detection = engine.generate(
            detection
        )
    """

    # ======================================================
    # Public Method
    # ======================================================

    def generate(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate recommendations for one detection.

        The original dictionary is not modified.

        Added fields
        ------------
        response_priority

        investigation_recommendations

        containment_recommendations

        remediation_recommendations

        prevention_recommendations

        recommendations
            Combined flattened recommendation list.
    """

        if not isinstance(
            detection,
            dict,
        ):
            raise TypeError(
                "Detection must be a dictionary."
            )

        result = deepcopy(
            detection
        )

        detection_type = _clean(
            detection.get(
                "detection_type"
            )
        )

        severity = _clean(
            detection.get(
                "severity"
            )
        )

        risk_score = _safe_int(
            detection.get(
                "risk_score"
            )
        )

        # ==================================================
        # 1. Determine Response Priority
        # ==================================================

        response_priority = (
            self._determine_priority(
                severity=severity,
                risk_score=risk_score,
            )
        )

        # ==================================================
        # 2. Detection-Specific Recommendations
        # ==================================================

        recommendation_data = (
            self._recommend_for_detection(
                detection_type=detection_type,
                detection=detection,
            )
        )

        investigation = recommendation_data[
            "investigation"
        ]

        containment = recommendation_data[
            "containment"
        ]

        remediation = recommendation_data[
            "remediation"
        ]

        prevention = recommendation_data[
            "prevention"
        ]

        # ==================================================
        # 3. Severity-Based Recommendations
        # ==================================================

        severity_actions = (
            self._severity_recommendations(
                severity=severity
            )
        )

        investigation.extend(
            severity_actions[
                "investigation"
            ]
        )

        containment.extend(
            severity_actions[
                "containment"
            ]
        )

        # ==================================================
        # 4. Remove Duplicates
        # ==================================================

        investigation = _deduplicate(
            investigation
        )

        containment = _deduplicate(
            containment
        )

        remediation = _deduplicate(
            remediation
        )

        prevention = _deduplicate(
            prevention
        )

        # ==================================================
        # 5. Combined Recommendations
        # ==================================================

        combined = _deduplicate(

            investigation
            + containment
            + remediation
            + prevention
        )

        # ==================================================
        # 6. Enrich Detection
        # ==================================================

        result[
            "response_priority"
        ] = response_priority

        result[
            "investigation_recommendations"
        ] = investigation

        result[
            "containment_recommendations"
        ] = containment

        result[
            "remediation_recommendations"
        ] = remediation

        result[
            "prevention_recommendations"
        ] = prevention

        result[
            "recommendations"
        ] = combined

        return result


    # ======================================================
    # Priority Logic
    # ======================================================

    def _determine_priority(
        self,
        *,
        severity: Optional[str],
        risk_score: Optional[int],
    ) -> str:
        """
        Determine analyst response priority.

        Priority is related to severity but is kept as a
        separate field for dashboard triage.
        """

        severity_upper = (
            severity.upper()
            if severity
            else ""
        )

        if (
            severity_upper == "CRITICAL"
            or (
                risk_score is not None
                and risk_score >= 80
            )
        ):
            return PRIORITY_IMMEDIATE

        if (
            severity_upper == "HIGH"
            or (
                risk_score is not None
                and risk_score >= 50
            )
        ):
            return PRIORITY_URGENT

        if (
            severity_upper == "MEDIUM"
            or (
                risk_score is not None
                and risk_score >= 30
            )
        ):
            return PRIORITY_STANDARD

        return PRIORITY_ROUTINE


    # ======================================================
    # Detection Router
    # ======================================================

    def _recommend_for_detection(
        self,
        *,
        detection_type: Optional[str],
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:
        """
        Route a detection to the appropriate recommendation
        method.
        """

        if (
            detection_type
            == "Repeated Local Authentication Failures"
        ):

            return (
                self._local_authentication_failures(
                    detection
                )
            )

        if (
            detection_type
            == "Potential Brute Force"
        ):

            return (
                self._potential_brute_force(
                    detection
                )
            )

        if (
            detection_type
            == "Multiple Failed Authentication Attempts"
        ):

            return (
                self._unknown_authentication_failures(
                    detection
                )
            )

        if (
            detection_type
            == "Suspicious PowerShell Activity"
        ):

            return (
                self._suspicious_powershell(
                    detection
                )
            )

        if (
            detection_type
            == "Suspicious Command Execution"
        ):

            return (
                self._suspicious_command(
                    detection
                )
            )

        if (
            detection_type
            == "User Account Created"
        ):

            return (
                self._user_created(
                    detection
                )
            )

        if (
            detection_type
            == "User Account Deleted"
        ):

            return (
                self._user_deleted(
                    detection
                )
            )

        if (
            detection_type
            == "Security Group Membership Modified"
        ):

            return (
                self._group_modified(
                    detection
                )
            )

        if (
            detection_type
            == "New Service Installed"
        ):

            return (
                self._service_installed(
                    detection
                )
            )

        if (
            detection_type
            == "Scheduled Task Created"
        ):

            return (
                self._scheduled_task_created(
                    detection
                )
            )

        if (
            detection_type
            == "Security Audit Log Cleared"
        ):

            return (
                self._audit_log_cleared(
                    detection
                )
            )

        return (
            self._generic_recommendations(
                detection
            )
        )


    # ======================================================
    # Local Authentication Failures
    # ======================================================

    def _local_authentication_failures(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        username = _clean(
            detection.get(
                "username"
            )
        )

        investigation = [

            (
                "Review the failed authentication events "
                "and confirm whether they were caused by "
                "the legitimate user."
            ),

            (
                "Check for successful logons occurring "
                "shortly after the failed attempts."
            ),

            (
                "Review the affected host for repeated "
                "authentication failures over a longer "
                "time period."
            ),
        ]

        if username:

            investigation.append(

                (
                    f"Review recent authentication activity "
                    f"for account '{username}'."
                )
            )

        containment = [

            (
                "Do not automatically disable the account "
                "based only on a small number of local "
                "password failures."
            ),
        ]

        remediation = [

            (
                "If the failures were legitimate user "
                "mistakes, verify that no further security "
                "action is required."
            ),

            (
                "If unauthorized activity is confirmed, "
                "secure the affected account and review "
                "related sessions."
            ),
        ]

        prevention = [

            (
                "Maintain an appropriate account lockout "
                "policy and monitor repeated authentication "
                "failures."
            ),

            (
                "Use multi-factor authentication where "
                "supported."
            ),
        ]

        return {

            "investigation":
                investigation,

            "containment":
                containment,

            "remediation":
                remediation,

            "prevention":
                prevention,
        }


    # ======================================================
    # Potential Brute Force
    # ======================================================

    def _potential_brute_force(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        source_ip = _clean(
            detection.get(
                "source_ip"
            )
        )

        username = _clean(
            detection.get(
                "username"
            )
        )

        investigation = [

            (
                "Review all failed authentication events "
                "associated with the source."
            ),

            (
                "Check whether a successful authentication "
                "occurred after the failed attempts."
            ),

            (
                "Review other systems for authentication "
                "attempts from the same source."
            ),
        ]

        if source_ip:

            investigation.append(

                (
                    f"Investigate source IP "
                    f"'{source_ip}' and determine whether "
                    f"it is expected in the environment."
                )
            )

        if username:

            investigation.append(

                (
                    f"Review account '{username}' for "
                    f"unexpected logons, password changes, "
                    f"or privilege changes."
                )
            )

        containment = [

            (
                "If the source is confirmed malicious, "
                "consider blocking or restricting it at "
                "the appropriate network control point."
            ),

            (
                "If account compromise is suspected, "
                "restrict the affected account according "
                "to incident response procedures."
            ),
        ]

        remediation = [

            (
                "Reset affected credentials if compromise "
                "is confirmed or strongly suspected."
            ),

            (
                "Terminate unauthorized authenticated "
                "sessions if compromise is confirmed."
            ),
        ]

        prevention = [

            (
                "Use multi-factor authentication for "
                "remote access where supported."
            ),

            (
                "Review account lockout and authentication "
                "rate-limiting controls."
            ),

            (
                "Restrict remote authentication exposure "
                "to trusted networks where possible."
            ),
        ]

        return {

            "investigation":
                investigation,

            "containment":
                containment,

            "remediation":
                remediation,

            "prevention":
                prevention,
        }


    # ======================================================
    # Unknown Authentication Context
    # ======================================================

    def _unknown_authentication_failures(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Determine whether the failed "
                    "authentication attempts originated "
                    "locally or remotely."
                ),

                (
                    "Review source, account, logon type, "
                    "and surrounding authentication events."
                ),

                (
                    "Check whether any successful logon "
                    "followed the failures."
                ),
            ],

            "containment": [

                (
                    "Apply containment only after validating "
                    "whether the activity is unauthorized."
                ),
            ],

            "remediation": [

                (
                    "Secure affected credentials if "
                    "unauthorized access is confirmed."
                ),
            ],

            "prevention": [

                (
                    "Maintain authentication monitoring, "
                    "account lockout controls, and MFA "
                    "where appropriate."
                ),
            ],
        }


    # ======================================================
    # Suspicious PowerShell
    # ======================================================

    def _suspicious_powershell(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Review the complete PowerShell script "
                    "block and command-line content."
                ),

                (
                    "Identify the user account and parent "
                    "process responsible for execution."
                ),

                (
                    "Review related process creation and "
                    "network activity around the same time."
                ),

                (
                    "Determine whether the PowerShell "
                    "activity was authorized administrative "
                    "activity."
                ),
            ],

            "containment": [

                (
                    "If malicious execution is confirmed, "
                    "isolate the affected endpoint according "
                    "to incident response procedures."
                ),

                (
                    "Restrict compromised credentials if "
                    "the execution originated from an "
                    "unauthorized account."
                ),
            ],

            "remediation": [

                (
                    "Remove malicious scripts, payloads, "
                    "scheduled tasks, services, or other "
                    "persistence identified during "
                    "investigation."
                ),

                (
                    "Review the endpoint for additional "
                    "indicators of compromise."
                ),
            ],

            "prevention": [

                (
                    "Maintain PowerShell Script Block "
                    "Logging and process creation auditing."
                ),

                (
                    "Use application control and PowerShell "
                    "security controls appropriate to the "
                    "environment."
                ),

                (
                    "Restrict unnecessary administrative "
                    "privileges."
                ),
            ],
        }


    # ======================================================
    # Suspicious Command
    # ======================================================

    def _suspicious_command(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Review the full command line, process, "
                    "parent process, user, and execution "
                    "time."
                ),

                (
                    "Determine whether the command was "
                    "authorized administrative activity."
                ),

                (
                    "Review related processes and system "
                    "changes before and after execution."
                ),
            ],

            "containment": [

                (
                    "If malicious activity is confirmed, "
                    "contain the affected endpoint and "
                    "restrict compromised accounts."
                ),
            ],

            "remediation": [

                (
                    "Reverse unauthorized system changes "
                    "where safely possible."
                ),

                (
                    "Restore affected security controls, "
                    "backups, or recovery settings if they "
                    "were modified."
                ),
            ],

            "prevention": [

                (
                    "Apply least privilege and application "
                    "control to reduce unauthorized command "
                    "execution."
                ),

                (
                    "Maintain command-line process auditing."
                ),
            ],
        }


    # ======================================================
    # User Created
    # ======================================================

    def _user_created(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Verify whether the new account creation "
                    "was authorized."
                ),

                (
                    "Identify the account that created the "
                    "new user."
                ),

                (
                    "Review the new account's group "
                    "memberships and subsequent logon "
                    "activity."
                ),
            ],

            "containment": [

                (
                    "If the account is unauthorized, "
                    "disable or restrict it according to "
                    "incident response procedures."
                ),
            ],

            "remediation": [

                (
                    "Remove unauthorized accounts after "
                    "preserving required investigation "
                    "evidence."
                ),
            ],

            "prevention": [

                (
                    "Restrict account creation privileges "
                    "to authorized administrators."
                ),

                (
                    "Audit account creation and privileged "
                    "group membership changes."
                ),
            ],
        }


    # ======================================================
    # User Deleted
    # ======================================================

    def _user_deleted(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Verify whether the account deletion "
                    "was authorized."
                ),

                (
                    "Identify the administrator or process "
                    "responsible for the deletion."
                ),

                (
                    "Review related account-management "
                    "events around the same time."
                ),
            ],

            "containment": [

                (
                    "If unauthorized administrative "
                    "activity is suspected, restrict the "
                    "responsible account while investigating."
                ),
            ],

            "remediation": [

                (
                    "Restore required accounts using "
                    "approved recovery procedures if the "
                    "deletion was unauthorized."
                ),
            ],

            "prevention": [

                (
                    "Restrict account-management privileges "
                    "and audit privileged administrative "
                    "changes."
                ),
            ],
        }


    # ======================================================
    # Group Modification
    # ======================================================

    def _group_modified(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Identify the account added to the "
                    "security group."
                ),

                (
                    "Verify whether the membership change "
                    "was authorized."
                ),

                (
                    "Review subsequent privileged activity "
                    "performed by the modified account."
                ),
            ],

            "containment": [

                (
                    "If unauthorized, remove the account "
                    "from the privileged group and restrict "
                    "the responsible credentials."
                ),
            ],

            "remediation": [

                (
                    "Review and correct unauthorized "
                    "privilege assignments."
                ),
            ],

            "prevention": [

                (
                    "Apply least privilege and monitor "
                    "changes to privileged security groups."
                ),
            ],
        }


    # ======================================================
    # Service Installed
    # ======================================================

    def _service_installed(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Verify whether the new service "
                    "installation was authorized."
                ),

                (
                    "Review the service executable path, "
                    "account, start type, and file "
                    "reputation."
                ),

                (
                    "Review the parent activity that caused "
                    "the service installation."
                ),
            ],

            "containment": [

                (
                    "If malicious, stop and isolate the "
                    "service only after preserving required "
                    "investigation evidence."
                ),
            ],

            "remediation": [

                (
                    "Remove unauthorized service persistence "
                    "and associated malicious files."
                ),
            ],

            "prevention": [

                (
                    "Restrict service installation rights "
                    "and monitor new service creation."
                ),
            ],
        }


    # ======================================================
    # Scheduled Task
    # ======================================================

    def _scheduled_task_created(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Review the scheduled task name, "
                    "trigger, action, execution account, "
                    "and creator."
                ),

                (
                    "Determine whether the task is expected "
                    "administrative or application activity."
                ),
            ],

            "containment": [

                (
                    "If the task is malicious, disable it "
                    "according to incident response "
                    "procedures while preserving evidence."
                ),
            ],

            "remediation": [

                (
                    "Remove unauthorized scheduled tasks "
                    "and investigate associated payloads."
                ),
            ],

            "prevention": [

                (
                    "Monitor scheduled-task creation and "
                    "restrict administrative privileges."
                ),
            ],
        }


    # ======================================================
    # Audit Log Cleared
    # ======================================================

    def _audit_log_cleared(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Identify the account and process "
                    "responsible for clearing the Security "
                    "audit log."
                ),

                (
                    "Determine whether the action was "
                    "authorized administrative activity."
                ),

                (
                    "Review centralized or forwarded logs "
                    "for activity preceding the log clear."
                ),

                (
                    "Search for other evidence of defense "
                    "evasion or compromise on the host."
                ),
            ],

            "containment": [

                (
                    "If unauthorized log clearing is "
                    "confirmed, prioritize containment of "
                    "the affected endpoint."
                ),

                (
                    "Restrict compromised privileged "
                    "accounts associated with the activity."
                ),
            ],

            "remediation": [

                (
                    "Restore logging and forwarding "
                    "configuration if it was altered."
                ),

                (
                    "Perform a broader compromise assessment "
                    "because local forensic evidence may "
                    "have been removed."
                ),
            ],

            "prevention": [

                (
                    "Forward security logs to a centralized "
                    "or protected logging system."
                ),

                (
                    "Restrict privileges capable of "
                    "clearing security logs."
                ),

                (
                    "Alert immediately on audit-log "
                    "clearing events."
                ),
            ],
        }


    # ======================================================
    # Generic Recommendations
    # ======================================================

    def _generic_recommendations(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, List[str]]:

        return {

            "investigation": [

                (
                    "Review the detection evidence and "
                    "surrounding Windows events."
                ),

                (
                    "Determine whether the activity is "
                    "authorized or unexpected."
                ),
            ],

            "containment": [

                (
                    "Apply containment only if malicious "
                    "or unauthorized activity is confirmed."
                ),
            ],

            "remediation": [

                (
                    "Correct unauthorized changes identified "
                    "during investigation."
                ),
            ],

            "prevention": [

                (
                    "Review relevant security controls and "
                    "monitor for recurrence."
                ),
            ],
        }


    # ======================================================
    # Severity-Based Recommendations
    # ======================================================

    def _severity_recommendations(
        self,
        *,
        severity: Optional[str],
    ) -> Dict[str, List[str]]:
        """
        Add general analyst guidance based on severity.
        """

        severity_upper = (
            severity.upper()
            if severity
            else ""
        )

        investigation: List[str] = []

        containment: List[str] = []

        if severity_upper == "CRITICAL":

            investigation.append(

                (
                    "Escalate this detection for immediate "
                    "SOC analyst review."
                )
            )

            containment.append(

                (
                    "Prepare containment actions promptly "
                    "if malicious activity is validated."
                )
            )

        elif severity_upper == "HIGH":

            investigation.append(

                (
                    "Prioritize this detection for prompt "
                    "SOC analyst investigation."
                )
            )

        elif severity_upper == "MEDIUM":

            investigation.append(

                (
                    "Review this detection as part of the "
                    "normal SOC investigation queue."
                )
            )

        return {

            "investigation":
                investigation,

            "containment":
                containment,
        }


# ==========================================================
# Development Output
# ==========================================================

def print_recommendations(
    detection: Dict[str, Any],
) -> None:
    """
    Print recommendation information during development.
    """

    print()

    print(
        "=" * 76
    )

    print(
        "SOC ANALYST RECOMMENDATIONS"
    )

    print(
        "=" * 76
    )

    fields = [

        "detection_type",

        "risk_score",
        "severity",

        "response_priority",

        "source_ip",

        "hostname",
        "host_ip",

        "mitre_tactic",
        "mitre_technique_id",
        "mitre_technique_name",

    ]

    for field in fields:

        value = detection.get(
            field
        )

        if value is not None:

            print(
                f"{field:<28}: {value}"
            )

    sections = [

        (
            "Investigation",
            "investigation_recommendations",
        ),

        (
            "Containment",
            "containment_recommendations",
        ),

        (
            "Remediation",
            "remediation_recommendations",
        ),

        (
            "Prevention",
            "prevention_recommendations",
        ),

    ]

    for title, key in sections:

        items = detection.get(
            key,
            []
        )

        if not items:
            continue

        print()

        print(
            f"{title}:"
        )

        for index, item in enumerate(
            items,
            start=1,
        ):

            print(
                f"  {index}. {item}"
            )

    print()

    print(
        "=" * 76
    )


# ==========================================================
# Standalone Tests
# ==========================================================

def _run_test() -> None:
    """
    Test Recommendation Engine independently.
    """

    engine = RecommendationEngine()

    print()

    print(
        "Recommendation Engine Test"
    )

    print(
        "-" * 50
    )

    # ======================================================
    # Test 1
    # Local Authentication Failures
    # ======================================================

    local_failures = {

        "detection_type":
            "Repeated Local Authentication Failures",

        "severity":
            "HIGH",

        "risk_score":
            50,

        "source_ip":
            "127.0.0.1",

        "authentication_scope":
            "local",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "mitre_mapped":
            False,
    }

    result = engine.generate(
        local_failures
    )

    print()

    print(
        "Test 1 - Local Authentication Failures"
    )

    print_recommendations(
        result
    )

    # ======================================================
    # Test 2
    # Potential Brute Force
    # ======================================================

    brute_force = {

        "detection_type":
            "Potential Brute Force",

        "severity":
            "CRITICAL",

        "risk_score":
            85,

        "source_ip":
            "192.168.1.50",

        "authentication_scope":
            "remote",

        "username":
            "testuser",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "mitre_mapped":
            True,

        "mitre_tactic":
            "Credential Access",

        "mitre_technique_id":
            "T1110",

        "mitre_technique_name":
            "Brute Force",
    }

    result = engine.generate(
        brute_force
    )

    print()

    print(
        "Test 2 - Potential Brute Force"
    )

    print_recommendations(
        result
    )

    # ======================================================
    # Test 3
    # Suspicious PowerShell
    # ======================================================

    powershell = {

        "detection_type":
            "Suspicious PowerShell Activity",

        "severity":
            "CRITICAL",

        "risk_score":
            90,

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "mitre_mapped":
            True,

        "mitre_tactic":
            "Execution",

        "mitre_technique_id":
            "T1059.001",

        "mitre_technique_name":
            "PowerShell",
    }

    result = engine.generate(
        powershell
    )

    print()

    print(
        "Test 3 - Suspicious PowerShell"
    )

    print_recommendations(
        result
    )

    # ======================================================
    # Test 4
    # Audit Log Cleared
    # ======================================================

    log_cleared = {

        "detection_type":
            "Security Audit Log Cleared",

        "severity":
            "CRITICAL",

        "risk_score":
            95,

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "mitre_mapped":
            True,

        "mitre_tactic":
            "Defense Evasion",

        "mitre_technique_id":
            "T1070.001",

        "mitre_technique_name":
            "Indicator Removal: Clear Windows Event Logs",
    }

    result = engine.generate(
        log_cleared
    )

    print()

    print(
        "Test 4 - Security Audit Log Cleared"
    )

    print_recommendations(
        result
    )


if __name__ == "__main__":

    _run_test()