"""
report_generator.py

Purpose
-------
Generate professional PDF incident reports for the
Intelligent SOC Assistant.

Flow
----
Incident ID
    ↓
SQLite Database
    ↓
Retrieve Full Incident
    ↓
Build PDF
    ↓
Save Report
    ↓
Return Report Path

The report includes:
- Incident summary
- Detection details
- Source and host information
- Timeline
- Severity and risk
- MITRE ATT&CK mapping
- Evidence
- Windows Event Record IDs
- Severity reasoning
- SOC recommendations
- Analyst status and notes
"""

from __future__ import annotations

import os
import sys

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors

from reportlab.lib.enums import (
    TA_CENTER,
    TA_LEFT,
)

from reportlab.lib.pagesizes import A4

from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)

from reportlab.lib.units import mm

from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from database.database import (
    DatabaseManager,
)


# ==========================================================
# Application Paths
# ==========================================================

PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent


def get_reports_directory() -> Path:
    """
    Return writable reports directory.

    Development:
        project/reports/generated/

    Packaged Windows EXE:
        %LOCALAPPDATA%/
        IntelligentSOCAssistant/
        reports/
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

        reports_dir = (
            base_dir
            / "IntelligentSOCAssistant"
            / "reports"
        )

    else:

        reports_dir = (
            PROJECT_ROOT
            / "reports"
            / "generated"
        )

    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    return reports_dir


DEFAULT_REPORTS_DIRECTORY = (
    get_reports_directory()
)


# ==========================================================
# Helper Functions
# ==========================================================

def _display(
    value: Any,
    default: str = "Not Available",
) -> str:
    """
    Convert values into report-safe display text.
    """

    if value is None:

        return default

    value = str(
        value
    ).strip()

    if not value:

        return default

    if value.lower() in {
        "none",
        "null",
        "n/a",
    }:

        return default

    return value


def _escape(
    value: Any,
) -> str:
    """
    Escape basic XML/HTML characters used by
    ReportLab Paragraph.
    """

    text = _display(
        value
    )

    return (
        text
        .replace(
            "&",
            "&amp;",
        )
        .replace(
            "<",
            "&lt;",
        )
        .replace(
            ">",
            "&gt;",
        )
    )


def _safe_filename(
    value: str,
) -> str:
    """
    Convert a string into a safe Windows filename.
    """

    invalid = (
        '<>:"/\\|?*'
    )

    result = str(
        value
    )

    for character in invalid:

        result = result.replace(
            character,
            "_",
        )

    return result.strip()


def _format_timestamp(
    value: Any,
) -> str:
    """
    Display ISO timestamps in a readable format.

    Keeps timezone information when available.
    """

    if value is None:

        return "Not Available"

    text = str(
        value
    ).strip()

    if not text:

        return "Not Available"

    try:

        parsed = datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00",
            )
        )

        if parsed.tzinfo is not None:

            return parsed.strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            ).strip()

        return parsed.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:

        return text


def _ensure_list(
    value: Any,
) -> List[Any]:
    """
    Convert supported values to a list.
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


# ==========================================================
# Report Generator
# ==========================================================

class IncidentReportGenerator:
    """
    Generate PDF reports from incidents stored in SQLite.
    """

    def __init__(
        self,
        database_manager: Optional[
            DatabaseManager
        ] = None,
        output_directory: Optional[
            str | Path
        ] = None,
    ) -> None:

        if database_manager is None:

            self.database = (
                DatabaseManager()
            )

        else:

            self.database = (
                database_manager
            )

        if output_directory is None:

            self.output_directory = (
                DEFAULT_REPORTS_DIRECTORY
            )

        else:

            self.output_directory = Path(
                output_directory
            ).expanduser().resolve()

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.styles = (
            self._build_styles()
        )


    # ======================================================
    # Styles
    # ======================================================

    def _build_styles(
        self,
    ) -> Dict[str, ParagraphStyle]:
        """
        Build report paragraph styles.
        """

        sample = (
            getSampleStyleSheet()
        )

        return {

            "title":
                ParagraphStyle(

                    "SOCReportTitle",

                    parent=sample[
                        "Title"
                    ],

                    fontName=
                        "Helvetica-Bold",

                    fontSize=22,

                    leading=27,

                    alignment=
                        TA_CENTER,

                    spaceAfter=6 * mm,
                ),

            "subtitle":
                ParagraphStyle(

                    "SOCReportSubtitle",

                    parent=sample[
                        "Normal"
                    ],

                    fontName=
                        "Helvetica",

                    fontSize=10,

                    leading=14,

                    alignment=
                        TA_CENTER,

                    textColor=
                        colors.HexColor(
                            "#555555"
                        ),

                    spaceAfter=6 * mm,
                ),

            "section":
                ParagraphStyle(

                    "SOCSection",

                    parent=sample[
                        "Heading2"
                    ],

                    fontName=
                        "Helvetica-Bold",

                    fontSize=14,

                    leading=18,

                    textColor=
                        colors.HexColor(
                            "#1F2937"
                        ),

                    spaceBefore=5 * mm,

                    spaceAfter=3 * mm,
                ),

            "normal":
                ParagraphStyle(

                    "SOCNormal",

                    parent=sample[
                        "BodyText"
                    ],

                    fontName=
                        "Helvetica",

                    fontSize=9,

                    leading=13,

                    alignment=
                        TA_LEFT,

                    spaceAfter=2 * mm,
                ),

            "small":
                ParagraphStyle(

                    "SOCSmall",

                    parent=sample[
                        "BodyText"
                    ],

                    fontName=
                        "Helvetica",

                    fontSize=8,

                    leading=11,

                    textColor=
                        colors.HexColor(
                            "#555555"
                        ),
                ),

            "bullet":
                ParagraphStyle(

                    "SOCBullet",

                    parent=sample[
                        "BodyText"
                    ],

                    fontName=
                        "Helvetica",

                    fontSize=9,

                    leading=13,

                    leftIndent=5 * mm,

                    firstLineIndent=
                        -3 * mm,

                    spaceAfter=2 * mm,
                ),

            "recommendation_heading":
                ParagraphStyle(

                    "SOCRecommendationHeading",

                    parent=sample[
                        "Heading3"
                    ],

                    fontName=
                        "Helvetica-Bold",

                    fontSize=10,

                    leading=14,

                    spaceBefore=3 * mm,

                    spaceAfter=2 * mm,
                ),
        }


    # ======================================================
    # Generate Report
    # ======================================================

    def generate_report(
        self,
        incident_id: str,
        output_path: Optional[
            str | Path
        ] = None,
    ) -> Path:
        """
        Generate a PDF report for one incident.

        Returns
        -------
        Path
            Generated PDF path.
        """

        incident = (
            self.database.get_incident(
                incident_id
            )
        )

        if incident is None:

            raise ValueError(

                f"Incident not found: "
                f"{incident_id}"
            )

        if output_path is None:

            filename = (
                _safe_filename(
                    incident_id
                )
                + ".pdf"
            )

            report_path = (
                self.output_directory
                / filename
            )

        else:

            report_path = Path(
                output_path
            ).expanduser().resolve()

            if (
                report_path.suffix.lower()
                != ".pdf"
            ):

                report_path = (
                    report_path.with_suffix(
                        ".pdf"
                    )
                )

            report_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._build_pdf(
            incident=incident,
            report_path=report_path,
        )

        return report_path


    # ======================================================
    # Build PDF
    # ======================================================

    def _build_pdf(
        self,
        *,
        incident: Dict[str, Any],
        report_path: Path,
    ) -> None:
        """
        Build complete PDF.
        """

        document = BaseDocTemplate(

            str(
                report_path
            ),

            pagesize=A4,

            rightMargin=15 * mm,

            leftMargin=15 * mm,

            topMargin=18 * mm,

            bottomMargin=18 * mm,

            title=(
                "Intelligent SOC Assistant "
                "Incident Report"
            ),

            author=
                "Intelligent SOC Assistant",
        )

        frame = Frame(

            document.leftMargin,

            document.bottomMargin,

            document.width,

            document.height,

            id="normal",
        )

        page_template = PageTemplate(

            id="SOCReport",

            frames=[
                frame
            ],

            onPage=self._draw_header_footer,
        )

        document.addPageTemplates(
            [
                page_template
            ]
        )

        story = []

        # ==================================================
        # Title
        # ==================================================

        story.append(

            Paragraph(

                "INTELLIGENT SOC ASSISTANT",

                self.styles[
                    "title"
                ],
            )
        )

        story.append(

            Paragraph(

                "Security Incident Report",

                self.styles[
                    "subtitle"
                ],
            )
        )

        # ==================================================
        # Incident Header
        # ==================================================

        story.extend(
            self._build_incident_header(
                incident
            )
        )

        # ==================================================
        # Executive Summary
        # ==================================================

        story.extend(
            self._build_executive_summary(
                incident
            )
        )

        # ==================================================
        # Detection Details
        # ==================================================

        story.extend(
            self._build_detection_details(
                incident
            )
        )

        # ==================================================
        # Source / Host
        # ==================================================

        story.extend(
            self._build_source_host_section(
                incident
            )
        )

        # ==================================================
        # Timeline
        # ==================================================

        story.extend(
            self._build_timeline_section(
                incident
            )
        )

        # ==================================================
        # Risk / Severity
        # ==================================================

        story.extend(
            self._build_risk_section(
                incident
            )
        )

        # ==================================================
        # MITRE
        # ==================================================

        story.extend(
            self._build_mitre_section(
                incident
            )
        )

        # ==================================================
        # Evidence
        # ==================================================

        story.extend(
            self._build_evidence_section(
                incident
            )
        )

        # ==================================================
        # Recommendations
        # ==================================================

        story.extend(
            self._build_recommendations_section(
                incident
            )
        )

        # ==================================================
        # Analyst Section
        # ==================================================

        story.extend(
            self._build_analyst_section(
                incident
            )
        )

        # ==================================================
        # Final Notice
        # ==================================================

        story.append(
            Spacer(
                1,
                6 * mm,
            )
        )

        story.append(

            Paragraph(

                (
                    "<b>Report Note:</b> "
                    "This report was generated from "
                    "security telemetry analyzed by the "
                    "Intelligent SOC Assistant. "
                    "Detections and recommendations should "
                    "be validated by a security analyst "
                    "before containment or remediation "
                    "actions are performed."
                ),

                self.styles[
                    "small"
                ],
            )
        )

        document.build(
            story
        )


    # ======================================================
    # Header / Footer
    # ======================================================

    def _draw_header_footer(
        self,
        canvas,
        document,
    ) -> None:
        """
        Draw page header and footer.
        """

        canvas.saveState()

        width, height = A4

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.setFillColor(
            colors.HexColor(
                "#666666"
            )
        )

        canvas.drawString(

            15 * mm,

            height - 10 * mm,

            "Intelligent SOC Assistant"
        )

        canvas.drawRightString(

            width - 15 * mm,

            height - 10 * mm,

            "Security Incident Report"
        )

        canvas.setStrokeColor(
            colors.HexColor(
                "#CCCCCC"
            )
        )

        canvas.line(

            15 * mm,

            height - 12 * mm,

            width - 15 * mm,

            height - 12 * mm,
        )

        canvas.line(

            15 * mm,

            12 * mm,

            width - 15 * mm,

            12 * mm,
        )

        canvas.drawString(

            15 * mm,

            7 * mm,

            "Generated by Intelligent SOC Assistant"
        )

        canvas.drawRightString(

            width - 15 * mm,

            7 * mm,

            f"Page {document.page}"
        )

        canvas.restoreState()


    # ======================================================
    # Incident Header
    # ======================================================

    def _build_incident_header(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        severity = _display(
            incident.get(
                "severity"
            )
        )

        data = [

            [
                Paragraph(
                    "<b>Incident ID</b>",
                    self.styles["normal"],
                ),

                Paragraph(
                    _escape(
                        incident.get(
                            "incident_id"
                        )
                    ),
                    self.styles["normal"],
                ),

                Paragraph(
                    "<b>Status</b>",
                    self.styles["normal"],
                ),

                Paragraph(
                    _escape(
                        incident.get(
                            "status"
                        )
                    ),
                    self.styles["normal"],
                ),
            ],

            [
                Paragraph(
                    "<b>Severity</b>",
                    self.styles["normal"],
                ),

                Paragraph(
                    _escape(
                        severity
                    ),
                    self.styles["normal"],
                ),

                Paragraph(
                    "<b>Priority</b>",
                    self.styles["normal"],
                ),

                Paragraph(
                    _escape(
                        incident.get(
                            "response_priority"
                        )
                    ),
                    self.styles["normal"],
                ),
            ],

            [
                Paragraph(
                    "<b>Created</b>",
                    self.styles["normal"],
                ),

                Paragraph(
                    _escape(
                        _format_timestamp(
                            incident.get(
                                "created_at"
                            )
                        )
                    ),
                    self.styles["normal"],
                ),

                Paragraph(
                    "<b>Risk Score</b>",
                    self.styles["normal"],
                ),

                Paragraph(
                    _escape(
                        incident.get(
                            "risk_score"
                        )
                    ),
                    self.styles["normal"],
                ),
            ],
        ]

        table = Table(

            data,

            colWidths=[
                28 * mm,
                62 * mm,
                28 * mm,
                62 * mm,
            ],

            repeatRows=0,
        )

        table.setStyle(

            TableStyle(
                [

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        colors.HexColor(
                            "#F5F7FA"
                        ),
                    ),

                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor(
                            "#D1D5DB"
                        ),
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),

                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        return [

            table,

            Spacer(
                1,
                4 * mm,
            ),
        ]


    # ======================================================
    # Executive Summary
    # ======================================================

    def _build_executive_summary(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        elements = [

            Paragraph(

                "1. Executive Summary",

                self.styles[
                    "section"
                ],
            )
        ]

        detection_type = _display(
            incident.get(
                "detection_type"
            )
        )

        severity = _display(
            incident.get(
                "severity"
            )
        )

        risk_score = _display(
            incident.get(
                "risk_score"
            )
        )

        host = _display(
            incident.get(
                "hostname"
            )
        )

        summary = (

            f"The Intelligent SOC Assistant detected "
            f"<b>{_escape(detection_type)}</b> on host "
            f"<b>{_escape(host)}</b>. "

            f"The incident was assigned severity "
            f"<b>{_escape(severity)}</b> with a risk "
            f"score of <b>{_escape(risk_score)}</b>. "
        )

        description = (
            incident.get(
                "description"
            )
        )

        if description:

            summary += _escape(
                description
            )

        elements.append(

            Paragraph(

                summary,

                self.styles[
                    "normal"
                ],
            )
        )

        return elements


    # ======================================================
    # Detection Details
    # ======================================================

    def _build_detection_details(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        rows = [

            (
                "Detection Type",
                incident.get(
                    "detection_type"
                ),
            ),

            (
                "Category",
                incident.get(
                    "detection_category"
                ),
            ),

            (
                "Confidence",
                incident.get(
                    "confidence"
                ),
            ),

            (
                "Windows Event ID",
                incident.get(
                    "event_id"
                ),
            ),

            (
                "Event Count",
                incident.get(
                    "event_count"
                ),
            ),

            (
                "Threshold",
                incident.get(
                    "threshold_value"
                ),
            ),
        ]

        return [

            Paragraph(

                "2. Detection Details",

                self.styles[
                    "section"
                ],
            ),

            self._two_column_table(
                rows
            ),
        ]


    # ======================================================
    # Source / Host
    # ======================================================

    def _build_source_host_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        rows = [

            (
                "Source IP",
                incident.get(
                    "source_ip"
                ),
            ),

            (
                "Source Port",
                incident.get(
                    "source_port"
                ),
            ),

            (
                "Destination IP",
                incident.get(
                    "destination_ip"
                ),
            ),

            (
                "Destination Port",
                incident.get(
                    "destination_port"
                ),
            ),

            (
                "Authentication Scope",
                incident.get(
                    "authentication_scope"
                ),
            ),

            (
                "Username",
                incident.get(
                    "username"
                ),
            ),

            (
                "Domain",
                incident.get(
                    "domain"
                ),
            ),

            (
                "Hostname",
                incident.get(
                    "hostname"
                ),
            ),

            (
                "Host IP",
                incident.get(
                    "host_ip"
                ),
            ),

            (
                "Logon Type",
                incident.get(
                    "logon_type"
                ),
            ),

            (
                "Logon Type Name",
                incident.get(
                    "logon_type_name"
                ),
            ),

            (
                "Process",
                incident.get(
                    "process_name"
                ),
            ),

            (
                "Parent Process",
                incident.get(
                    "parent_process_name"
                ),
            ),

            (
                "Command Line",
                incident.get(
                    "command_line"
                ),
            ),
        ]

        return [

            Paragraph(

                "3. Source, User and Host Information",

                self.styles[
                    "section"
                ],
            ),

            self._two_column_table(
                rows
            ),
        ]


    # ======================================================
    # Timeline
    # ======================================================

    def _build_timeline_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        rows = [

            (
                "First Seen",
                _format_timestamp(
                    incident.get(
                        "first_seen"
                    )
                ),
            ),

            (
                "Last Seen",
                _format_timestamp(
                    incident.get(
                        "last_seen"
                    )
                ),
            ),

            (
                "Incident Created",
                _format_timestamp(
                    incident.get(
                        "created_at"
                    )
                ),
            ),
        ]

        return [

            Paragraph(

                "4. Incident Timeline",

                self.styles[
                    "section"
                ],
            ),

            self._two_column_table(
                rows
            ),
        ]


    # ======================================================
    # Risk Section
    # ======================================================

    def _build_risk_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        elements = [

            Paragraph(

                "5. Severity and Risk Assessment",

                self.styles[
                    "section"
                ],
            )
        ]

        rows = [

            (
                "Base Risk Score",
                incident.get(
                    "base_risk_score"
                ),
            ),

            (
                "Final Risk Score",
                incident.get(
                    "risk_score"
                ),
            ),

            (
                "Severity",
                incident.get(
                    "severity"
                ),
            ),

            (
                "Response Priority",
                incident.get(
                    "response_priority"
                ),
            ),
        ]

        elements.append(
            self._two_column_table(
                rows
            )
        )

        reasons = _ensure_list(
            incident.get(
                "severity_reasons"
            )
        )

        if reasons:

            elements.append(

                Paragraph(

                    "Risk Scoring Reasons",

                    self.styles[
                        "recommendation_heading"
                    ],
                )
            )

            elements.extend(
                self._bullet_items(
                    reasons
                )
            )

        return elements


    # ======================================================
    # MITRE
    # ======================================================

    def _build_mitre_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        elements = [

            Paragraph(

                "6. MITRE ATT&CK Mapping",

                self.styles[
                    "section"
                ],
            )
        ]

        if not incident.get(
            "mitre_mapped"
        ):

            elements.append(

                Paragraph(

                    (
                        "No direct MITRE ATT&CK mapping "
                        "was assigned to this detection."
                    ),

                    self.styles[
                        "normal"
                    ],
                )
            )

            return elements

        rows = [

            (
                "Tactic",
                incident.get(
                    "mitre_tactic"
                ),
            ),

            (
                "Technique ID",
                incident.get(
                    "mitre_technique_id"
                ),
            ),

            (
                "Technique Name",
                incident.get(
                    "mitre_technique_name"
                ),
            ),
        ]

        elements.append(
            self._two_column_table(
                rows
            )
        )

        mappings = _ensure_list(
            incident.get(
                "mitre_mappings"
            )
        )

        if len(
            mappings
        ) > 1:

            elements.append(

                Paragraph(

                    "Additional Mappings",

                    self.styles[
                        "recommendation_heading"
                    ],
                )
            )

            mapping_rows = [

                [
                    Paragraph(
                        "<b>Tactic</b>",
                        self.styles[
                            "normal"
                        ],
                    ),

                    Paragraph(
                        "<b>Technique</b>",
                        self.styles[
                            "normal"
                        ],
                    ),

                    Paragraph(
                        "<b>Name</b>",
                        self.styles[
                            "normal"
                        ],
                    ),
                ]
            ]

            for mapping in mappings:

                if not isinstance(
                    mapping,
                    dict,
                ):

                    continue

                mapping_rows.append(

                    [

                        Paragraph(
                            _escape(
                                mapping.get(
                                    "tactic"
                                )
                            ),
                            self.styles[
                                "normal"
                            ],
                        ),

                        Paragraph(
                            _escape(
                                mapping.get(
                                    "technique_id"
                                )
                            ),
                            self.styles[
                                "normal"
                            ],
                        ),

                        Paragraph(
                            _escape(
                                mapping.get(
                                    "technique_name"
                                )
                            ),
                            self.styles[
                                "normal"
                            ],
                        ),
                    ]
                )

            table = Table(

                mapping_rows,

                colWidths=[
                    50 * mm,
                    35 * mm,
                    95 * mm,
                ],

                repeatRows=1,
            )

            table.setStyle(
                self._standard_table_style()
            )

            elements.append(
                table
            )

        return elements


    # ======================================================
    # Evidence
    # ======================================================

    def _build_evidence_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        elements = [

            Paragraph(

                "7. Detection Evidence",

                self.styles[
                    "section"
                ],
            )
        ]

        evidence = _ensure_list(
            incident.get(
                "evidence"
            )
        )

        if evidence:

            elements.extend(
                self._bullet_items(
                    evidence
                )
            )

        else:

            elements.append(

                Paragraph(

                    "No additional evidence text stored.",

                    self.styles[
                        "normal"
                    ],
                )
            )

        record_ids = _ensure_list(
            incident.get(
                "record_ids"
            )
        )

        if record_ids:

            elements.append(

                Paragraph(

                    "Windows Event Record IDs",

                    self.styles[
                        "recommendation_heading"
                    ],
                )
            )

            record_text = ", ".join(
                str(
                    item
                )
                for item in record_ids
            )

            elements.append(

                Paragraph(

                    _escape(
                        record_text
                    ),

                    self.styles[
                        "normal"
                    ],
                )
            )

        return elements


    # ======================================================
    # Recommendations
    # ======================================================

    def _build_recommendations_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        elements = [

            Paragraph(

                "8. Recommended SOC Actions",

                self.styles[
                    "section"
                ],
            )
        ]

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

        found = False

        for title, key in sections:

            items = _ensure_list(
                incident.get(
                    key
                )
            )

            if not items:

                continue

            found = True

            elements.append(

                Paragraph(

                    title,

                    self.styles[
                        "recommendation_heading"
                    ],
                )
            )

            elements.extend(
                self._bullet_items(
                    items
                )
            )

        if not found:

            elements.append(

                Paragraph(

                    "No recommendations were stored.",

                    self.styles[
                        "normal"
                    ],
                )
            )

        return elements


    # ======================================================
    # Analyst Section
    # ======================================================

    def _build_analyst_section(
        self,
        incident: Dict[str, Any],
    ) -> List[Any]:

        rows = [

            (
                "Incident Status",
                incident.get(
                    "status"
                ),
            ),

            (
                "Analyst Notes",
                incident.get(
                    "analyst_notes"
                ),
            ),
        ]

        return [

            Paragraph(

                "9. Analyst Review",

                self.styles[
                    "section"
                ],
            ),

            self._two_column_table(
                rows
            ),
        ]


    # ======================================================
    # Generic Two-Column Table
    # ======================================================

    def _two_column_table(
        self,
        rows: List[Any],
    ) -> Table:

        data = []

        for label, value in rows:

            data.append(

                [

                    Paragraph(

                        f"<b>{_escape(label)}</b>",

                        self.styles[
                            "normal"
                        ],
                    ),

                    Paragraph(

                        _escape(
                            value
                        ),

                        self.styles[
                            "normal"
                        ],
                    ),
                ]
            )

        table = Table(

            data,

            colWidths=[
                55 * mm,
                125 * mm,
            ],

            repeatRows=0,
        )

        table.setStyle(
            self._standard_table_style()
        )

        return table


    # ======================================================
    # Standard Table Style
    # ======================================================

    def _standard_table_style(
        self,
    ) -> TableStyle:

        return TableStyle(
            [

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#D1D5DB"
                    ),
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#F5F7FA"
                    ),
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )


    # ======================================================
    # Bullet Items
    # ======================================================

    def _bullet_items(
        self,
        items: List[Any],
    ) -> List[Paragraph]:

        paragraphs = []

        for item in items:

            if item is None:

                continue

            paragraphs.append(

                Paragraph(

                    "&#8226;&nbsp;&nbsp;"
                    + _escape(
                        item
                    ),

                    self.styles[
                        "bullet"
                    ],
                )
            )

        return paragraphs


# ==========================================================
# Standalone Development Test
# ==========================================================

def _run_test() -> None:
    """
    Generate a report from the most recent REAL incident.

    This does not create fake incident data.
    """

    database = DatabaseManager()

    database.initialize_database()

    incidents = (
        database.get_recent_incidents(
            limit=1
        )
    )

    print()

    print(
        "Incident Report Generator Test"
    )

    print(
        "-" * 60
    )

    if not incidents:

        print(
            "[ERROR] No incidents found in the real database."
        )

        print(
            "Generate at least one live detection first."
        )

        return

    incident_id = incidents[
        0
    ][
        "incident_id"
    ]

    print(
        f"Using incident: "
        f"{incident_id}"
    )

    generator = (
        IncidentReportGenerator(
            database_manager=database
        )
    )

    report_path = (
        generator.generate_report(
            incident_id
        )
    )

    print(
        "[OK] PDF report generated."
    )

    print(
        f"Report path: "
        f"{report_path}"
    )

    print()

    print(
        "=" * 60
    )

    print(
        "REPORT GENERATION TEST PASSED"
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":

    _run_test()