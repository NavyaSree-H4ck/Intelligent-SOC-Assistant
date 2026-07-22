"""
database.py

Purpose
-------
SQLite persistence layer for the Intelligent SOC Assistant.

Responsibilities
----------------
1. Initialize the SQLite database.
2. Store enriched security incidents.
3. Store evidence, record IDs, MITRE mappings,
   severity reasons, and recommendations.
4. Retrieve incidents for the desktop dashboard.
5. Provide dashboard statistics.
6. Update incident status and analyst notes.

The database stores DETECTIONS / INCIDENTS,
not every raw Windows event.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid

from datetime import datetime, timezone
from pathlib import Path

from typing import Any, Dict, List, Optional


# ==========================================================
# Paths
# ==========================================================

PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent


def _get_schema_path() -> Path:
    """
    Return schema.sql path.

    Supports both normal Python execution and a future
    PyInstaller bundle.
    """

    if getattr(
        sys,
        "frozen",
        False,
    ):

        bundle_root = Path(
            getattr(
                sys,
                "_MEIPASS",
                Path(
                    sys.executable
                ).resolve().parent,
            )
        )

        return (
            bundle_root
            / "database"
            / "schema.sql"
        )

    return (
        Path(
            __file__
        ).resolve().parent
        / "schema.sql"
    )


def _get_default_database_path() -> Path:
    """
    Return a writable database path.

    Development:
        project/data/soc_assistant.db

    Packaged Windows EXE:
        %LOCALAPPDATA%/IntelligentSOCAssistant/
        soc_assistant.db

    This prevents the future EXE from trying to write into
    a protected installation directory.
    """

    if getattr(
        sys,
        "frozen",
        False,
    ):

        base_dir = Path(
            os.environ.get(
                "LOCALAPPDATA",
                Path.home(),
            )
        )

        data_dir = (
            base_dir
            / "IntelligentSOCAssistant"
        )

    else:

        data_dir = (
            PROJECT_ROOT
            / "data"
        )

    data_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    return (
        data_dir
        / "soc_assistant.db"
    )


SCHEMA_PATH = _get_schema_path()

DEFAULT_DATABASE_PATH = (
    _get_default_database_path()
)


# ==========================================================
# Helper Functions
# ==========================================================

def _clean(
    value: Any,
) -> Optional[str]:
    """
    Convert a value into a clean string or None.
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


def _ensure_list(
    value: Any,
) -> List[Any]:
    """
    Convert supported values into a list.
    """

    if value is None:

        return []

    if isinstance(
        value,
        list,
    ):

        return value

    if isinstance(
        value,
        tuple,
    ):

        return list(
            value
        )

    return [
        value
    ]


def _json_default(
    value: Any,
) -> str:
    """
    JSON serializer fallback for values such as datetime.
    """

    if isinstance(
        value,
        datetime,
    ):

        return value.isoformat()

    return str(
        value
    )


# ==========================================================
# Database Manager
# ==========================================================

class DatabaseManager:
    """
    Main SQLite database interface.
    """

    def __init__(
        self,
        database_path: Optional[
            str | Path
        ] = None,
    ) -> None:

        if database_path is None:

            self.database_path = (
                DEFAULT_DATABASE_PATH
            )

        else:

            self.database_path = Path(
                database_path
            ).expanduser().resolve()

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


    # ======================================================
    # Connection
    # ======================================================

    def _connect(
        self,
    ) -> sqlite3.Connection:

        connection = sqlite3.connect(
            str(
                self.database_path
            ),
            timeout=30,
        )

        connection.row_factory = (
            sqlite3.Row
        )

        connection.execute(
            "PRAGMA foreign_keys = ON;"
        )

        connection.execute(
            "PRAGMA busy_timeout = 5000;"
        )

        return connection


    # ======================================================
    # Initialize Database
    # ======================================================

    def initialize_database(
        self,
    ) -> None:
        """
        Create tables and indexes from schema.sql.
        """

        if not SCHEMA_PATH.exists():

            raise FileNotFoundError(

                f"Database schema not found: "
                f"{SCHEMA_PATH}"
            )

        schema_sql = (
            SCHEMA_PATH.read_text(
                encoding="utf-8"
            )
        )

        with self._connect() as connection:

            connection.executescript(
                schema_sql
            )

            connection.commit()


    # ======================================================
    # Generate Incident ID
    # ======================================================

    def _generate_incident_id(
        self,
    ) -> str:
        """
        Generate a readable unique incident ID.

        Example:
        INC-20260721-002412-AB12CD34
        """

        now = datetime.now(
            timezone.utc
        )

        random_part = (
            uuid.uuid4()
            .hex[:8]
            .upper()
        )

        return (

            "INC-"
            + now.strftime(
                "%Y%m%d-%H%M%S"
            )
            + "-"
            + random_part
        )


    # ======================================================
    # Insert Incident
    # ======================================================

    def insert_incident(
        self,
        detection: Dict[str, Any],
    ) -> str:
        """
        Store one fully enriched detection as an incident.

        Returns
        -------
        incident_id
        """

        if not isinstance(
            detection,
            dict,
        ):

            raise TypeError(
                "Detection must be a dictionary."
            )

        detection_type = _clean(
            detection.get(
                "detection_type"
            )
        )

        if detection_type is None:

            raise ValueError(
                "Detection is missing detection_type."
            )

        incident_id = (
            self._generate_incident_id()
        )

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        raw_json = json.dumps(

            detection,

            ensure_ascii=False,

            default=_json_default,
        )

        mitre_mapped = (
            1
            if detection.get(
                "mitre_mapped"
            )
            else 0
        )

        with self._connect() as connection:

            try:

                connection.execute(

                    """
                    INSERT INTO incidents (

                        incident_id,
                        created_at,

                        detection_type,
                        detection_category,
                        description,
                        confidence,

                        event_id,
                        event_count,
                        threshold_value,

                        first_seen,
                        last_seen,

                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,

                        authentication_scope,

                        username,
                        domain,

                        hostname,
                        host_ip,

                        logon_type,
                        logon_type_name,

                        process_name,
                        parent_process_name,
                        command_line,

                        base_risk_score,
                        risk_score,
                        severity,

                        response_priority,

                        mitre_mapped,
                        mitre_tactic,
                        mitre_technique_id,
                        mitre_technique_name,

                        status,
                        analyst_notes,

                        raw_detection_json

                    )
                    VALUES (

                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?

                    )
                    """,

                    (

                        incident_id,
                        created_at,

                        detection_type,

                        _clean(
                            detection.get(
                                "detection_category"
                            )
                        ),

                        _clean(
                            detection.get(
                                "description"
                            )
                        ),

                        _clean(
                            detection.get(
                                "confidence"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "event_id"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "event_count"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "threshold"
                            )
                        ),

                        _clean(
                            detection.get(
                                "first_seen"
                            )
                        ),

                        _clean(
                            detection.get(
                                "last_seen"
                            )
                        ),

                        _clean(
                            detection.get(
                                "source_ip"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "source_port"
                            )
                        ),

                        _clean(
                            detection.get(
                                "destination_ip"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "destination_port"
                            )
                        ),

                        _clean(
                            detection.get(
                                "authentication_scope"
                            )
                        ),

                        _clean(
                            detection.get(
                                "username"
                            )
                        ),

                        _clean(
                            detection.get(
                                "domain"
                            )
                        ),

                        _clean(
                            detection.get(
                                "hostname"
                            )
                        ),

                        _clean(
                            detection.get(
                                "host_ip"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "logon_type"
                            )
                        ),

                        _clean(
                            detection.get(
                                "logon_type_name"
                            )
                        ),

                        _clean(
                            detection.get(
                                "process_name"
                            )
                        ),

                        _clean(
                            detection.get(
                                "parent_process_name"
                            )
                        ),

                        _clean(
                            detection.get(
                                "command_line"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "base_risk_score"
                            )
                        ),

                        _safe_int(
                            detection.get(
                                "risk_score"
                            )
                        ),

                        _clean(
                            detection.get(
                                "severity"
                            )
                        ),

                        _clean(
                            detection.get(
                                "response_priority"
                            )
                        ),

                        mitre_mapped,

                        _clean(
                            detection.get(
                                "mitre_tactic"
                            )
                        ),

                        _clean(
                            detection.get(
                                "mitre_technique_id"
                            )
                        ),

                        _clean(
                            detection.get(
                                "mitre_technique_name"
                            )
                        ),

                        "OPEN",

                        None,

                        raw_json,
                    ),
                )

                self._insert_evidence(
                    connection,
                    incident_id,
                    detection,
                )

                self._insert_record_ids(
                    connection,
                    incident_id,
                    detection,
                )

                self._insert_mitre_mappings(
                    connection,
                    incident_id,
                    detection,
                )

                self._insert_severity_reasons(
                    connection,
                    incident_id,
                    detection,
                )

                self._insert_recommendations(
                    connection,
                    incident_id,
                    detection,
                )

                connection.commit()

            except Exception:

                connection.rollback()

                raise

        return incident_id


    # ======================================================
    # Insert Evidence
    # ======================================================

    def _insert_evidence(
        self,
        connection: sqlite3.Connection,
        incident_id: str,
        detection: Dict[str, Any],
    ) -> None:

        evidence_items = _ensure_list(
            detection.get(
                "evidence"
            )
        )

        for index, item in enumerate(
            evidence_items,
            start=1,
        ):

            text = _clean(
                item
            )

            if text is None:

                continue

            connection.execute(

                """
                INSERT INTO incident_evidence (

                    incident_id,
                    evidence_order,
                    evidence_text

                )
                VALUES (?, ?, ?)
                """,

                (
                    incident_id,
                    index,
                    text,
                ),
            )


    # ======================================================
    # Insert Record IDs
    # ======================================================

    def _insert_record_ids(
        self,
        connection: sqlite3.Connection,
        incident_id: str,
        detection: Dict[str, Any],
    ) -> None:

        record_ids = _ensure_list(
            detection.get(
                "record_ids"
            )
        )

        # Some single-event detections may contain record_id
        # instead of record_ids.

        if not record_ids:

            single_record_id = (
                detection.get(
                    "record_id"
                )
            )

            if single_record_id is not None:

                record_ids = [
                    single_record_id
                ]

        seen = set()

        for record_id in record_ids:

            text = _clean(
                record_id
            )

            if text is None:

                continue

            if text in seen:

                continue

            seen.add(
                text
            )

            connection.execute(

                """
                INSERT INTO incident_record_ids (

                    incident_id,
                    record_id

                )
                VALUES (?, ?)
                """,

                (
                    incident_id,
                    text,
                ),
            )


    # ======================================================
    # Insert MITRE Mappings
    # ======================================================

    def _insert_mitre_mappings(
        self,
        connection: sqlite3.Connection,
        incident_id: str,
        detection: Dict[str, Any],
    ) -> None:

        mappings = _ensure_list(
            detection.get(
                "mitre_mappings"
            )
        )

        for mapping in mappings:

            if not isinstance(
                mapping,
                dict,
            ):

                continue

            connection.execute(

                """
                INSERT INTO incident_mitre_mappings (

                    incident_id,
                    tactic,
                    technique_id,
                    technique_name

                )
                VALUES (?, ?, ?, ?)
                """,

                (

                    incident_id,

                    _clean(
                        mapping.get(
                            "tactic"
                        )
                    ),

                    _clean(
                        mapping.get(
                            "technique_id"
                        )
                    ),

                    _clean(
                        mapping.get(
                            "technique_name"
                        )
                    ),
                ),
            )


    # ======================================================
    # Insert Severity Reasons
    # ======================================================

    def _insert_severity_reasons(
        self,
        connection: sqlite3.Connection,
        incident_id: str,
        detection: Dict[str, Any],
    ) -> None:

        reasons = _ensure_list(
            detection.get(
                "severity_reasons"
            )
        )

        for index, reason in enumerate(
            reasons,
            start=1,
        ):

            text = _clean(
                reason
            )

            if text is None:

                continue

            connection.execute(

                """
                INSERT INTO incident_severity_reasons (

                    incident_id,
                    reason_order,
                    reason_text

                )
                VALUES (?, ?, ?)
                """,

                (
                    incident_id,
                    index,
                    text,
                ),
            )


    # ======================================================
    # Insert Recommendations
    # ======================================================

    def _insert_recommendations(
        self,
        connection: sqlite3.Connection,
        incident_id: str,
        detection: Dict[str, Any],
    ) -> None:

        recommendation_fields = {

            "INVESTIGATION":
                "investigation_recommendations",

            "CONTAINMENT":
                "containment_recommendations",

            "REMEDIATION":
                "remediation_recommendations",

            "PREVENTION":
                "prevention_recommendations",
        }

        for (
            recommendation_type,
            field_name,
        ) in recommendation_fields.items():

            items = _ensure_list(
                detection.get(
                    field_name
                )
            )

            for index, item in enumerate(
                items,
                start=1,
            ):

                text = _clean(
                    item
                )

                if text is None:

                    continue

                connection.execute(

                    """
                    INSERT INTO incident_recommendations (

                        incident_id,
                        recommendation_type,
                        recommendation_order,
                        recommendation_text

                    )
                    VALUES (?, ?, ?, ?)
                    """,

                    (

                        incident_id,
                        recommendation_type,
                        index,
                        text,
                    ),
                )


    # ======================================================
    # Get Incident
    # ======================================================

    def get_incident(
        self,
        incident_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Return one incident with child data.
        """

        with self._connect() as connection:

            row = connection.execute(

                """
                SELECT *
                FROM incidents
                WHERE incident_id = ?
                """,

                (
                    incident_id,
                ),

            ).fetchone()

            if row is None:

                return None

            incident = dict(
                row
            )

            incident[
                "mitre_mapped"
            ] = bool(
                incident.get(
                    "mitre_mapped"
                )
            )

            incident[
                "evidence"
            ] = [

                item[
                    "evidence_text"
                ]

                for item in connection.execute(

                    """
                    SELECT evidence_text
                    FROM incident_evidence
                    WHERE incident_id = ?
                    ORDER BY evidence_order, id
                    """,

                    (
                        incident_id,
                    ),

                ).fetchall()
            ]

            incident[
                "record_ids"
            ] = [

                item[
                    "record_id"
                ]

                for item in connection.execute(

                    """
                    SELECT record_id
                    FROM incident_record_ids
                    WHERE incident_id = ?
                    ORDER BY id
                    """,

                    (
                        incident_id,
                    ),

                ).fetchall()
            ]

            incident[
                "mitre_mappings"
            ] = [

                dict(
                    item
                )

                for item in connection.execute(

                    """
                    SELECT
                        tactic,
                        technique_id,
                        technique_name

                    FROM incident_mitre_mappings

                    WHERE incident_id = ?

                    ORDER BY id
                    """,

                    (
                        incident_id,
                    ),

                ).fetchall()
            ]

            incident[
                "severity_reasons"
            ] = [

                item[
                    "reason_text"
                ]

                for item in connection.execute(

                    """
                    SELECT reason_text
                    FROM incident_severity_reasons
                    WHERE incident_id = ?
                    ORDER BY reason_order, id
                    """,

                    (
                        incident_id,
                    ),

                ).fetchall()
            ]

            recommendation_rows = (
                connection.execute(

                    """
                    SELECT
                        recommendation_type,
                        recommendation_text

                    FROM incident_recommendations

                    WHERE incident_id = ?

                    ORDER BY
                        recommendation_type,
                        recommendation_order,
                        id
                    """,

                    (
                        incident_id,
                    ),

                ).fetchall()
            )

            recommendation_map = {

                "INVESTIGATION":
                    [],

                "CONTAINMENT":
                    [],

                "REMEDIATION":
                    [],

                "PREVENTION":
                    [],
            }

            for item in recommendation_rows:

                recommendation_type = (
                    item[
                        "recommendation_type"
                    ]
                )

                if (
                    recommendation_type
                    in recommendation_map
                ):

                    recommendation_map[
                        recommendation_type
                    ].append(

                        item[
                            "recommendation_text"
                        ]
                    )

            incident[
                "investigation_recommendations"
            ] = recommendation_map[
                "INVESTIGATION"
            ]

            incident[
                "containment_recommendations"
            ] = recommendation_map[
                "CONTAINMENT"
            ]

            incident[
                "remediation_recommendations"
            ] = recommendation_map[
                "REMEDIATION"
            ]

            incident[
                "prevention_recommendations"
            ] = recommendation_map[
                "PREVENTION"
            ]

            incident[
                "recommendations"
            ] = (

                recommendation_map[
                    "INVESTIGATION"
                ]

                + recommendation_map[
                    "CONTAINMENT"
                ]

                + recommendation_map[
                    "REMEDIATION"
                ]

                + recommendation_map[
                    "PREVENTION"
                ]
            )

            return incident


    # ======================================================
    # List Incidents
    # ======================================================

    def get_recent_incidents(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Return recent incidents for the dashboard.
        """

        limit = max(
            1,
            min(
                int(
                    limit
                ),
                1000,
            ),
        )

        with self._connect() as connection:

            rows = connection.execute(

                """
                SELECT

                    incident_id,
                    created_at,

                    detection_type,
                    detection_category,

                    risk_score,
                    severity,

                    response_priority,

                    source_ip,

                    username,

                    hostname,
                    host_ip,

                    mitre_tactic,
                    mitre_technique_id,
                    mitre_technique_name,

                    status,

                    first_seen,
                    last_seen

                FROM incidents

                ORDER BY
                    created_at DESC,
                    id DESC

                LIMIT ?
                """,

                (
                    limit,
                ),

            ).fetchall()

            return [

                dict(
                    row
                )

                for row in rows
            ]


    # ======================================================
    # Search / Filter Incidents
    # ======================================================

    def search_incidents(
        self,
        *,
        search_text: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        detection_type: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Search incidents for the future desktop dashboard.
        """

        sql = """

            SELECT

                incident_id,
                created_at,

                detection_type,
                detection_category,

                risk_score,
                severity,

                response_priority,

                source_ip,

                username,

                hostname,
                host_ip,

                mitre_tactic,
                mitre_technique_id,
                mitre_technique_name,

                status,

                first_seen,
                last_seen

            FROM incidents

            WHERE 1 = 1

        """

        parameters: List[Any] = []

        cleaned_search = _clean(
            search_text
        )

        cleaned_severity = _clean(
            severity
        )

        cleaned_status = _clean(
            status
        )

        cleaned_detection = _clean(
            detection_type
        )

        if cleaned_search:

            like_value = (
                f"%{cleaned_search}%"
            )

            sql += """

                AND (

                    incident_id LIKE ?

                    OR detection_type LIKE ?

                    OR source_ip LIKE ?

                    OR username LIKE ?

                    OR hostname LIKE ?

                    OR host_ip LIKE ?

                    OR mitre_technique_id LIKE ?

                    OR mitre_technique_name LIKE ?
                )

            """

            parameters.extend(
                [
                    like_value,
                    like_value,
                    like_value,
                    like_value,
                    like_value,
                    like_value,
                    like_value,
                    like_value,
                ]
            )

        if cleaned_severity:

            sql += """

                AND UPPER(severity) = UPPER(?)

            """

            parameters.append(
                cleaned_severity
            )

        if cleaned_status:

            sql += """

                AND UPPER(status) = UPPER(?)

            """

            parameters.append(
                cleaned_status
            )

        if cleaned_detection:

            sql += """

                AND detection_type = ?

            """

            parameters.append(
                cleaned_detection
            )

        sql += """

            ORDER BY
                created_at DESC,
                id DESC

            LIMIT ?

        """

        limit = max(
            1,
            min(
                int(
                    limit
                ),
                5000,
            ),
        )

        parameters.append(
            limit
        )

        with self._connect() as connection:

            rows = connection.execute(

                sql,

                parameters,

            ).fetchall()

            return [

                dict(
                    row
                )

                for row in rows
            ]


    # ======================================================
    # Dashboard Statistics
    # ======================================================

    def get_dashboard_stats(
        self,
    ) -> Dict[str, Any]:
        """
        Return KPI statistics for the desktop dashboard.
        """

        with self._connect() as connection:

            total = connection.execute(

                """
                SELECT COUNT(*) AS count
                FROM incidents
                """

            ).fetchone()[
                "count"
            ]

            open_count = connection.execute(

                """
                SELECT COUNT(*) AS count
                FROM incidents
                WHERE status = 'OPEN'
                """

            ).fetchone()[
                "count"
            ]

            severity_rows = connection.execute(

                """
                SELECT
                    COALESCE(severity, 'UNKNOWN')
                        AS severity,

                    COUNT(*)
                        AS count

                FROM incidents

                GROUP BY
                    COALESCE(
                        severity,
                        'UNKNOWN'
                    )
                """

            ).fetchall()

            severity_counts = {

                row[
                    "severity"
                ]:
                    row[
                        "count"
                    ]

                for row in severity_rows
            }

            detection_rows = connection.execute(

                """
                SELECT
                    detection_type,
                    COUNT(*) AS count

                FROM incidents

                GROUP BY
                    detection_type

                ORDER BY
                    count DESC,
                    detection_type ASC
                """

            ).fetchall()

            detection_counts = {

                row[
                    "detection_type"
                ]:
                    row[
                        "count"
                    ]

                for row in detection_rows
            }

            return {

                "total_incidents":
                    total,

                "open_incidents":
                    open_count,

                "low":
                    severity_counts.get(
                        "LOW",
                        0,
                    ),

                "medium":
                    severity_counts.get(
                        "MEDIUM",
                        0,
                    ),

                "high":
                    severity_counts.get(
                        "HIGH",
                        0,
                    ),

                "critical":
                    severity_counts.get(
                        "CRITICAL",
                        0,
                    ),

                "severity_counts":
                    severity_counts,

                "detection_counts":
                    detection_counts,
            }


    # ======================================================
    # Update Incident Status
    # ======================================================

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
    ) -> None:
        """
        Update incident workflow status.

        Allowed:
        OPEN
        INVESTIGATING
        RESOLVED
        FALSE_POSITIVE
        """

        allowed_statuses = {

            "OPEN",

            "INVESTIGATING",

            "RESOLVED",

            "FALSE_POSITIVE",
        }

        status = str(
            status
        ).strip().upper()

        if (
            status
            not in allowed_statuses
        ):

            raise ValueError(

                "Invalid incident status. "
                "Allowed values: "
                "OPEN, INVESTIGATING, "
                "RESOLVED, FALSE_POSITIVE."
            )

        with self._connect() as connection:

            cursor = connection.execute(

                """
                UPDATE incidents
                SET status = ?
                WHERE incident_id = ?
                """,

                (
                    status,
                    incident_id,
                ),
            )

            if cursor.rowcount == 0:

                raise ValueError(
                    "Incident not found."
                )

            connection.commit()


    # ======================================================
    # Update Analyst Notes
    # ======================================================

    def update_analyst_notes(
        self,
        incident_id: str,
        notes: Optional[str],
    ) -> None:
        """
        Save analyst notes from the future desktop UI.
        """

        with self._connect() as connection:

            cursor = connection.execute(

                """
                UPDATE incidents
                SET analyst_notes = ?
                WHERE incident_id = ?
                """,

                (
                    _clean(
                        notes
                    ),

                    incident_id,
                ),
            )

            if cursor.rowcount == 0:

                raise ValueError(
                    "Incident not found."
                )

            connection.commit()


# ==========================================================
# Development Test
# ==========================================================

def _run_test() -> None:
    """
    Test database initialization and incident storage.

    Uses a separate test database so development tests do
    not pollute the real SOC incident database.
    """

    test_database_path = (

        PROJECT_ROOT
        / "data"
        / "soc_assistant_test.db"
    )

    if test_database_path.exists():

        test_database_path.unlink()

    database = DatabaseManager(
        test_database_path
    )

    print()

    print(
        "Database Layer Test"
    )

    print(
        "-" * 60
    )

    print(
        f"Database: {test_database_path}"
    )

    # ======================================================
    # 1. Initialize
    # ======================================================

    database.initialize_database()

    print(
        "[OK] Database initialized."
    )

    # ======================================================
    # 2. Example Enriched Incident
    # ======================================================

    test_detection = {

        "detection_type":
            "Potential Brute Force",

        "detection_category":
            "credential_access",

        "description":
            (
                "Multiple failed remote authentication "
                "attempts from the same source were "
                "observed within a short time window."
            ),

        "confidence":
            "high",

        "event_id":
            4625,

        "event_count":
            3,

        "threshold":
            3,

        "first_seen":
            "2026-07-20T18:43:46+00:00",

        "last_seen":
            "2026-07-20T18:43:51+00:00",

        "source_ip":
            "192.168.1.50",

        "destination_ip":
            "192.168.1.20",

        "authentication_scope":
            "remote",

        "username":
            "testuser",

        "hostname":
            "TEST-PC",

        "host_ip":
            "192.168.1.20",

        "logon_type":
            10,

        "logon_type_name":
            "Remote Interactive",

        "record_ids":
            [
                1001,
                1002,
                1003,
            ],

        "evidence":
            [
                (
                    "3 failed authentication events "
                    "were correlated."
                ),

                (
                    "Windows Event ID 4625 triggered "
                    "the correlation."
                ),

                (
                    "Source IP: 192.168.1.50"
                ),
            ],

        "base_risk_score":
            60,

        "risk_score":
            85,

        "severity":
            "CRITICAL",

        "severity_reasons":
            [
                (
                    "Base risk score for "
                    "'Potential Brute Force': 60"
                ),

                (
                    "Detection confidence 'high': +5"
                ),

                (
                    "Remote authentication source "
                    "increases exposure: +10"
                ),
            ],

        "mitre_mapped":
            True,

        "mitre_tactic":
            "Credential Access",

        "mitre_technique_id":
            "T1110",

        "mitre_technique_name":
            "Brute Force",

        "mitre_mappings":
            [
                {
                    "tactic":
                        "Credential Access",

                    "technique_id":
                        "T1110",

                    "technique_name":
                        "Brute Force",
                }
            ],

        "response_priority":
            "IMMEDIATE",

        "investigation_recommendations":
            [
                (
                    "Investigate the remote source IP."
                ),

                (
                    "Check whether a successful login "
                    "followed the failed attempts."
                ),
            ],

        "containment_recommendations":
            [
                (
                    "If confirmed malicious, consider "
                    "blocking or restricting the source."
                ),
            ],

        "remediation_recommendations":
            [
                (
                    "Reset affected credentials if "
                    "compromise is confirmed."
                ),
            ],

        "prevention_recommendations":
            [
                (
                    "Use multi-factor authentication "
                    "for remote access."
                ),
            ],
    }

    # ======================================================
    # 3. Insert
    # ======================================================

    incident_id = database.insert_incident(
        test_detection
    )

    print(
        f"[OK] Incident inserted: "
        f"{incident_id}"
    )

    # ======================================================
    # 4. Retrieve
    # ======================================================

    incident = database.get_incident(
        incident_id
    )

    if incident is None:

        raise RuntimeError(
            "Inserted incident could not be retrieved."
        )

    print(
        "[OK] Incident retrieved."
    )

    print()

    print(
        f"Detection : "
        f"{incident['detection_type']}"
    )

    print(
        f"Severity  : "
        f"{incident['severity']}"
    )

    print(
        f"Risk      : "
        f"{incident['risk_score']}"
    )

    print(
        f"MITRE     : "
        f"{incident['mitre_technique_id']}"
    )

    print(
        f"Status    : "
        f"{incident['status']}"
    )

    print(
        f"Evidence  : "
        f"{len(incident['evidence'])}"
    )

    print(
        f"Records   : "
        f"{len(incident['record_ids'])}"
    )

    print(
        f"Recommendations: "
        f"{len(incident['recommendations'])}"
    )

    # ======================================================
    # 5. Statistics
    # ======================================================

    stats = database.get_dashboard_stats()

    print()

    print(
        "Dashboard Statistics:"
    )

    print(
        stats
    )

    # ======================================================
    # 6. Status Update
    # ======================================================

    database.update_incident_status(
        incident_id,
        "INVESTIGATING",
    )

    updated = database.get_incident(
        incident_id
    )

    print()

    print(
        "[OK] Updated status: "
        f"{updated['status']}"
    )

    # ======================================================
    # 7. Notes
    # ======================================================

    database.update_analyst_notes(

        incident_id,

        (
            "Test incident created during "
            "database validation."
        ),
    )

    updated = database.get_incident(
        incident_id
    )

    print(
        "[OK] Analyst notes saved."
    )

    print()

    print(
        "=" * 60
    )

    print(
        "DATABASE TEST PASSED"
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":

    _run_test()