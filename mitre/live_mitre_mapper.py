"""
live_mitre_mapper.py

Purpose
-------
MITRE ATT&CK mapping module for the
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
1. Receive an existing security detection.
2. Map supported detections to MITRE ATT&CK.
3. Add tactic and technique information.
4. Preserve the original detection data.
5. Avoid forcing unsupported mappings.

Important
---------
This module does NOT:

- Detect attacks
- Correlate events
- Calculate severity
- Generate recommendations
- Store incidents

It only enriches detections with MITRE ATT&CK metadata.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional


# ==========================================================
# MITRE ATT&CK Mapping Table
# ==========================================================
#
# One detection may map to one or more ATT&CK techniques.
#
# We store mappings as a list so the architecture already
# supports multiple techniques later.
# ==========================================================

MITRE_MAPPINGS: Dict[str, List[Dict[str, str]]] = {

    # ------------------------------------------------------
    # Credential Access
    # ------------------------------------------------------

    "Potential Brute Force": [

        {
            "tactic":
                "Credential Access",

            "technique_id":
                "T1110",

            "technique_name":
                "Brute Force",
        }

    ],

    # ------------------------------------------------------
    # Execution
    # ------------------------------------------------------

    "Suspicious PowerShell Activity": [

        {
            "tactic":
                "Execution",

            "technique_id":
                "T1059.001",

            "technique_name":
                "PowerShell",
        }

    ],

    "Suspicious Command Execution": [

        {
            "tactic":
                "Execution",

            "technique_id":
                "T1059",

            "technique_name":
                "Command and Scripting Interpreter",
        }

    ],

    # ------------------------------------------------------
    # Persistence
    # ------------------------------------------------------

    "User Account Created": [

        {
            "tactic":
                "Persistence",

            "technique_id":
                "T1136.001",

            "technique_name":
                "Create Account: Local Account",
        }

    ],

    "New Service Installed": [

        {
            "tactic":
                "Persistence",

            "technique_id":
                "T1543.003",

            "technique_name":
                "Create or Modify System Process: "
                "Windows Service",
        }

    ],

    "Scheduled Task Created": [

        {
            "tactic":
                "Execution / Persistence",

            "technique_id":
                "T1053.005",

            "technique_name":
                "Scheduled Task/Job: Scheduled Task",
        }

    ],

    # ------------------------------------------------------
    # Privilege / Account Modification
    # ------------------------------------------------------

    "Security Group Membership Modified": [

        {
            "tactic":
                "Persistence / Privilege Escalation",

            "technique_id":
                "T1098",

            "technique_name":
                "Account Manipulation",
        }

    ],

    # ------------------------------------------------------
    # Defense Evasion
    # ------------------------------------------------------

    "Security Audit Log Cleared": [

        {
            "tactic":
                "Defense Evasion",

            "technique_id":
                "T1070.001",

            "technique_name":
                "Indicator Removal: Clear Windows Event Logs",
        }

    ],

}


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


# ==========================================================
# MITRE ATT&CK Mapper
# ==========================================================

class MitreMapper:
    """
    Enrich security detections with MITRE ATT&CK metadata.

    Usage
    -----

        mapper = MitreMapper()

        enriched_detection = mapper.map_detection(
            detection
        )
    """

    def map_detection(
        self,
        detection: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Map one detection to MITRE ATT&CK.

        The input dictionary is not modified.

        Added fields
        ------------
        mitre_mapped
        mitre_mappings
        mitre_tactic
        mitre_technique_id
        mitre_technique_name
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

        mappings = MITRE_MAPPINGS.get(
            detection_type,
            [],
        )

        # ==================================================
        # No Supported Mapping
        # ==================================================

        if not mappings:

            result[
                "mitre_mapped"
            ] = False

            result[
                "mitre_mappings"
            ] = []

            result[
                "mitre_tactic"
            ] = None

            result[
                "mitre_technique_id"
            ] = None

            result[
                "mitre_technique_name"
            ] = None

            return result

        # ==================================================
        # Supported Mapping
        # ==================================================

        copied_mappings = deepcopy(
            mappings
        )

        result[
            "mitre_mapped"
        ] = True

        result[
            "mitre_mappings"
        ] = copied_mappings

        # --------------------------------------------------
        # Convenience fields
        # --------------------------------------------------
        #
        # These represent the primary/first mapping and make
        # database and dashboard usage simpler.
        #
        # Full mappings remain available in mitre_mappings.
        # --------------------------------------------------

        primary = copied_mappings[
            0
        ]

        result[
            "mitre_tactic"
        ] = primary.get(
            "tactic"
        )

        result[
            "mitre_technique_id"
        ] = primary.get(
            "technique_id"
        )

        result[
            "mitre_technique_name"
        ] = primary.get(
            "technique_name"
        )

        return result


# ==========================================================
# Development Output
# ==========================================================

def print_mitre_mapping(
    detection: Dict[str, Any],
) -> None:
    """
    Print MITRE ATT&CK enrichment during development.
    """

    print()

    print(
        "=" * 76
    )

    print(
        "MITRE ATT&CK MAPPING"
    )

    print(
        "=" * 76
    )

    fields = [

        "detection_type",

        "risk_score",
        "severity",

        "source_ip",

        "hostname",
        "host_ip",

        "mitre_mapped",
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

    mappings = detection.get(
        "mitre_mappings",
        []
    )

    if mappings:

        print()

        print(
            "All MITRE Mappings:"
        )

        for mapping in mappings:

            print(
                "  - "
                f"{mapping.get('technique_id')} | "
                f"{mapping.get('technique_name')} | "
                f"{mapping.get('tactic')}"
            )

    elif detection.get(
        "mitre_mapped"
    ) is False:

        print()

        print(
            "MITRE Mapping:"
        )

        print(
            "  - No ATT&CK technique was automatically "
            "assigned for this detection."
        )

    print(
        "=" * 76
    )


# ==========================================================
# Standalone Tests
# ==========================================================

def _run_test() -> None:
    """
    Test the MITRE mapper independently.
    """

    mapper = MitreMapper()

    print()

    print(
        "MITRE ATT&CK Mapper Test"
    )

    print(
        "-" * 50
    )

    # ======================================================
    # Test 1
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

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",
    }

    result = mapper.map_detection(
        brute_force
    )

    print()

    print(
        "Test 1 - Potential Brute Force"
    )

    print_mitre_mapping(
        result
    )

    # ======================================================
    # Test 2
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
    }

    result = mapper.map_detection(
        powershell
    )

    print()

    print(
        "Test 2 - Suspicious PowerShell"
    )

    print_mitre_mapping(
        result
    )

    # ======================================================
    # Test 3
    # Security Audit Log Cleared
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
    }

    result = mapper.map_detection(
        log_cleared
    )

    print()

    print(
        "Test 3 - Security Audit Log Cleared"
    )

    print_mitre_mapping(
        result
    )

    # ======================================================
    # Test 4
    # Local Authentication Failures
    #
    # We deliberately do NOT map this automatically to
    # T1110 because three local password mistakes alone do
    # not prove adversary brute-force activity.
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

        "hostname":
            "TEST-PC",
    }

    result = mapper.map_detection(
        local_failures
    )

    print()

    print(
        "Test 4 - Repeated Local Authentication Failures"
    )

    print_mitre_mapping(
        result
    )


if __name__ == "__main__":

    _run_test()