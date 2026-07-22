"""
severity.py

Purpose
-------
Context-aware severity and risk scoring engine for the
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
Desktop Dashboard

Responsibilities
----------------
1. Receive a security detection.
2. Calculate a numeric risk score from 0 to 100.
3. Assign a severity:
       LOW
       MEDIUM
       HIGH
       CRITICAL
4. Consider detection type and contextual evidence.
5. Explain which factors affected the score.

Important
---------
This module does NOT:

- Detect attacks
- Correlate events
- Map MITRE ATT&CK
- Generate recommendations
- Write to the database

It only evaluates the severity of an existing detection.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple


# ==========================================================
# Severity Labels
# ==========================================================

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


# ==========================================================
# Base Risk Scores
# ==========================================================
#
# These scores represent the initial risk associated with
# each detection type before contextual adjustments.
#
# Final score is always restricted to:
#
#     0 <= score <= 100
#
# ==========================================================

BASE_RISK_SCORES = {

    # Authentication

    "Repeated Local Authentication Failures":
        35,

    "Potential Brute Force":
        60,

    "Multiple Failed Authentication Attempts":
        45,

    # Execution

    "Suspicious PowerShell Activity":
        60,

    "Suspicious Command Execution":
        65,

    # Account Management

    "User Account Created":
        40,

    "User Account Deleted":
        40,

    "Security Group Membership Modified":
        55,

    # Persistence / System Changes

    "New Service Installed":
        55,

    "Scheduled Task Created":
        50,

    # Defense Evasion

    "Security Audit Log Cleared":
        90,
}


# ==========================================================
# Confidence Score Adjustments
# ==========================================================

CONFIDENCE_ADJUSTMENTS = {

    "low":
        -5,

    "medium":
        0,

    "high":
        5,
}


# ==========================================================
# Helper Functions
# ==========================================================

def _clean(
    value: Any,
) -> Optional[str]:
    """
    Return a clean string or None.
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


def _safe_float(
    value: Any,
) -> Optional[float]:
    """
    Safely convert a value to float.
    """

    if value is None:
        return None

    try:
        return float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):
        return None


def _clamp_score(
    score: int,
) -> int:
    """
    Restrict a risk score to the range 0-100.
    """

    return max(
        0,
        min(
            int(score),
            100,
        ),
    )


def _score_to_severity(
    score: int,
) -> str:
    """
    Convert numeric risk score into severity.

    Ranges
    ------
    0-29   -> LOW
    30-49  -> MEDIUM
    50-79  -> HIGH
    80-100 -> CRITICAL
    """

    if score >= 80:
        return SEVERITY_CRITICAL

    if score >= 50:
        return SEVERITY_HIGH

    if score >= 30:
        return SEVERITY_MEDIUM

    return SEVERITY_LOW


# ==========================================================
# Severity Engine
# ==========================================================

class SeverityEngine:
    """
    Context-aware severity scoring engine.

    Usage
    -----

        engine = SeverityEngine()

        enriched_detection = engine.evaluate(
            detection
        )

    The original detection is not modified.
    A new enriched dictionary is returned.
    """

    # ======================================================
    # Public Evaluation Method
    # ======================================================

    def evaluate(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculate risk score and severity for one detection.

        Returns the original detection data plus:

            risk_score
            severity
            base_risk_score
            severity_reasons
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

        # ==================================================
        # 1. Base Risk Score
        # ==================================================

        base_score = BASE_RISK_SCORES.get(
            detection_type,
            30,
        )

        score = base_score

        reasons: List[str] = [

            (
                f"Base risk score for "
                f"'{detection_type or 'Unknown Detection'}': "
                f"{base_score}"
            )
        ]

        # ==================================================
        # 2. Confidence Adjustment
        # ==================================================

        confidence = _clean(
            detection.get(
                "confidence"
            )
        )

        if confidence is not None:

            confidence = confidence.lower()

            adjustment = (
                CONFIDENCE_ADJUSTMENTS.get(
                    confidence,
                    0,
                )
            )

            if adjustment != 0:

                score += adjustment

                sign = (
                    "+"
                    if adjustment > 0
                    else ""
                )

                reasons.append(
                    (
                        f"Detection confidence "
                        f"'{confidence}': "
                        f"{sign}{adjustment}"
                    )
                )

        # ==================================================
        # 3. Detection-Specific Context
        # ==================================================

        context_score, context_reasons = (
            self._evaluate_context(
                detection
            )
        )

        score += context_score

        reasons.extend(
            context_reasons
        )

        # ==================================================
        # 4. Clamp Final Score
        # ==================================================

        final_score = _clamp_score(
            score
        )

        severity = _score_to_severity(
            final_score
        )

        # ==================================================
        # 5. Add Severity Information
        # ==================================================

        result[
            "base_risk_score"
        ] = base_score

        result[
            "risk_score"
        ] = final_score

        result[
            "severity"
        ] = severity

        result[
            "severity_reasons"
        ] = reasons

        return result


    # ======================================================
    # Context Evaluation
    # ======================================================

    def _evaluate_context(
        self,
        detection: Dict[str, Any],
    ) -> Tuple[int, List[str]]:
        """
        Apply contextual score adjustments.

        This method keeps all contextual scoring logic in
        one place.
        """

        detection_type = _clean(
            detection.get(
                "detection_type"
            )
        )

        score_adjustment = 0

        reasons: List[str] = []

        # --------------------------------------------------
        # Authentication / Brute Force Context
        # --------------------------------------------------

        if detection_type in {

            "Repeated Local Authentication Failures",

            "Potential Brute Force",

            "Multiple Failed Authentication Attempts",

        }:

            adjustment, new_reasons = (
                self._authentication_context(
                    detection
                )
            )

            score_adjustment += adjustment

            reasons.extend(
                new_reasons
            )

        # --------------------------------------------------
        # Suspicious PowerShell
        # --------------------------------------------------

        elif (
            detection_type
            == "Suspicious PowerShell Activity"
        ):

            adjustment, new_reasons = (
                self._powershell_context(
                    detection
                )
            )

            score_adjustment += adjustment

            reasons.extend(
                new_reasons
            )

        # --------------------------------------------------
        # Suspicious Command
        # --------------------------------------------------

        elif (
            detection_type
            == "Suspicious Command Execution"
        ):

            adjustment, new_reasons = (
                self._command_context(
                    detection
                )
            )

            score_adjustment += adjustment

            reasons.extend(
                new_reasons
            )

        # --------------------------------------------------
        # Audit Log Cleared
        # --------------------------------------------------

        elif (
            detection_type
            == "Security Audit Log Cleared"
        ):

            reasons.append(
                (
                    "Clearing the Security audit log "
                    "can remove forensic evidence."
                )
            )

        return (
            score_adjustment,
            reasons,
        )


    # ======================================================
    # Authentication Context
    # ======================================================

    def _authentication_context(
        self,
        detection: Dict[str, Any],
    ) -> Tuple[int, List[str]]:
        """
        Evaluate failed-authentication context.
        """

        adjustment = 0

        reasons: List[str] = []

        event_count = _safe_int(
            detection.get(
                "event_count"
            )
        )

        observed_window = _safe_float(
            detection.get(
                "observed_window_seconds"
            )
        )

        authentication_scope = _clean(
            detection.get(
                "authentication_scope"
            )
        )

        # --------------------------------------------------
        # Remote Source
        # --------------------------------------------------

        if (
            authentication_scope is not None
            and authentication_scope.lower()
            == "remote"
        ):

            adjustment += 10

            reasons.append(
                (
                    "Remote authentication source "
                    "increases exposure: +10"
                )
            )

        # --------------------------------------------------
        # Event Count
        # --------------------------------------------------

        if event_count is not None:

            if event_count >= 10:

                adjustment += 15

                reasons.append(
                    (
                        f"High authentication failure count "
                        f"({event_count} events): +15"
                    )
                )

            elif event_count >= 5:

                adjustment += 10

                reasons.append(
                    (
                        f"Elevated authentication failure "
                        f"count ({event_count} events): +10"
                    )
                )

            elif event_count >= 3:

                adjustment += 5

                reasons.append(
                    (
                        f"Repeated authentication failures "
                        f"({event_count} events): +5"
                    )
                )

        # --------------------------------------------------
        # Rapid Attempts
        # --------------------------------------------------

        if (
            observed_window is not None
            and event_count is not None
            and event_count >= 3
            and observed_window <= 10
        ):

            adjustment += 5

            reasons.append(
                (
                    "Multiple authentication failures "
                    "occurred within 10 seconds: +5"
                )
            )

        return (
            adjustment,
            reasons,
        )


    # ======================================================
    # PowerShell Context
    # ======================================================

    def _powershell_context(
        self,
        detection: Dict[str, Any],
    ) -> Tuple[int, List[str]]:
        """
        Evaluate suspicious PowerShell context.
        """

        adjustment = 0

        reasons: List[str] = []

        evidence = detection.get(
            "evidence"
        )

        if not isinstance(
            evidence,
            list,
        ):
            evidence = []

        evidence_text = " ".join(
            str(item).lower()
            for item in evidence
        )

        # --------------------------------------------------
        # Encoded Commands
        # --------------------------------------------------

        if (
            "encoded powershell command"
            in evidence_text

            or
            "encoded powershell argument"
            in evidence_text
        ):

            adjustment += 10

            reasons.append(
                (
                    "Encoded PowerShell execution "
                    "detected: +10"
                )
            )

        # --------------------------------------------------
        # Execution Policy Bypass
        # --------------------------------------------------

        if (
            "execution policy bypass"
            in evidence_text
        ):

            adjustment += 10

            reasons.append(
                (
                    "PowerShell execution policy "
                    "bypass detected: +10"
                )
            )

        # --------------------------------------------------
        # Download / Web Activity
        # --------------------------------------------------

        download_indicators = [

            "remote content download",
            "remote file download",
            "web request",
            "webclient",
            "bits file transfer",
            "rest request",

        ]

        if any(
            indicator in evidence_text
            for indicator
            in download_indicators
        ):

            adjustment += 10

            reasons.append(
                (
                    "PowerShell network/download "
                    "behavior detected: +10"
                )
            )

        # --------------------------------------------------
        # Multiple Suspicious Indicators
        # --------------------------------------------------

        if len(
            evidence
        ) >= 3:

            adjustment += 5

            reasons.append(
                (
                    "Multiple suspicious PowerShell "
                    "indicators were observed: +5"
                )
            )

        return (
            adjustment,
            reasons,
        )


    # ======================================================
    # Suspicious Command Context
    # ======================================================

    def _command_context(
        self,
        detection: Dict[str, Any],
    ) -> Tuple[int, List[str]]:
        """
        Evaluate suspicious command execution context.
        """

        adjustment = 0

        reasons: List[str] = []

        evidence = detection.get(
            "evidence"
        )

        if not isinstance(
            evidence,
            list,
        ):
            evidence = []

        evidence_text = " ".join(
            str(item).lower()
            for item in evidence
        )

        # --------------------------------------------------
        # Shadow Copy / Backup Destruction
        # --------------------------------------------------

        destructive_indicators = [

            "shadow copies deletion",
            "shadow copies deletion through wmic",
            "backup deletion",
            "windows recovery disabled",
            "boot recovery policy modified",

        ]

        if any(
            indicator in evidence_text
            for indicator
            in destructive_indicators
        ):

            adjustment += 15

            reasons.append(
                (
                    "Recovery or backup tampering "
                    "behavior detected: +15"
                )
            )

        # --------------------------------------------------
        # Event Log Clearing Command
        # --------------------------------------------------

        if (
            "event log clearing"
            in evidence_text
        ):

            adjustment += 15

            reasons.append(
                (
                    "Command attempts to clear "
                    "Windows event logs: +15"
                )
            )

        # --------------------------------------------------
        # Account / Group Modification
        # --------------------------------------------------

        if (
            "user account creation"
            in evidence_text
        ):

            adjustment += 10

            reasons.append(
                (
                    "Command-line account creation "
                    "behavior detected: +10"
                )
            )

        if (
            "group membership modification"
            in evidence_text
        ):

            adjustment += 10

            reasons.append(
                (
                    "Command-line security group "
                    "modification detected: +10"
                )
            )

        return (
            adjustment,
            reasons,
        )


# ==========================================================
# Development Output
# ==========================================================

def print_severity(
    detection: Dict[str, Any],
) -> None:
    """
    Print severity information during development.
    """

    print()

    print(
        "=" * 76
    )

    print(
        "SEVERITY ASSESSMENT"
    )

    print(
        "=" * 76
    )

    fields = [

        "detection_type",
        "detection_category",

        "confidence",

        "base_risk_score",
        "risk_score",
        "severity",

        "source_ip",
        "authentication_scope",

        "hostname",
        "host_ip",

        "event_count",

        "first_seen",
        "last_seen",
    ]

    for field in fields:

        value = detection.get(
            field
        )

        if value is not None:

            print(
                f"{field:<28}: {value}"
            )

    reasons = detection.get(
        "severity_reasons",
        []
    )

    if reasons:

        print()

        print(
            "Severity Reasons:"
        )

        for reason in reasons:

            print(
                f"  - {reason}"
            )

    print(
        "=" * 76
    )


# ==========================================================
# Standalone Tests
# ==========================================================

def _run_test() -> None:
    """
    Test the Severity Engine independently.
    """

    engine = SeverityEngine()

    print()

    print(
        "Severity Engine Test"
    )

    print(
        "-" * 50
    )

    # ======================================================
    # Test 1
    # Repeated Local Authentication Failures
    # ======================================================

    local_failed_logins = {

        "detection_type":
            "Repeated Local Authentication Failures",

        "detection_category":
            "authentication",

        "confidence":
            "high",

        "event_id":
            4625,

        "event_count":
            3,

        "threshold":
            3,

        "observed_window_seconds":
            5.59,

        "source_ip":
            "127.0.0.1",

        "authentication_scope":
            "local",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",
    }

    result = engine.evaluate(
        local_failed_logins
    )

    print()

    print(
        "Test 1 - Local Authentication Failures"
    )

    print_severity(
        result
    )

    # ======================================================
    # Test 2
    # Remote Potential Brute Force
    # ======================================================

    remote_brute_force = {

        "detection_type":
            "Potential Brute Force",

        "detection_category":
            "credential_access",

        "confidence":
            "high",

        "event_id":
            4625,

        "event_count":
            3,

        "threshold":
            3,

        "observed_window_seconds":
            5.0,

        "source_ip":
            "192.168.1.50",

        "authentication_scope":
            "remote",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",
    }

    result = engine.evaluate(
        remote_brute_force
    )

    print()

    print(
        "Test 2 - Potential Brute Force"
    )

    print_severity(
        result
    )

    # ======================================================
    # Test 3
    # Suspicious PowerShell
    # ======================================================

    suspicious_powershell = {

        "detection_type":
            "Suspicious PowerShell Activity",

        "detection_category":
            "execution",

        "confidence":
            "high",

        "event_id":
            4104,

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "evidence": [

            "Encoded PowerShell command",

            "Encoded PowerShell argument",

            "Execution policy bypass",

        ],
    }

    result = engine.evaluate(
        suspicious_powershell
    )

    print()

    print(
        "Test 3 - Suspicious PowerShell"
    )

    print_severity(
        result
    )

    # ======================================================
    # Test 4
    # Audit Log Cleared
    # ======================================================

    audit_log_cleared = {

        "detection_type":
            "Security Audit Log Cleared",

        "detection_category":
            "defense_evasion",

        "confidence":
            "high",

        "event_id":
            1102,

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",
    }

    result = engine.evaluate(
        audit_log_cleared
    )

    print()

    print(
        "Test 4 - Security Audit Log Cleared"
    )

    print_severity(
        result
    )


if __name__ == "__main__":

    _run_test()