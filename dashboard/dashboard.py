"""
dashboard.py

Purpose
-------
Main PySide6 desktop interface for the
Intelligent SOC Assistant.

Step 15
-------
Desktop Application Foundation

Provides:
- Main application window
- Header
- Sidebar navigation
- Stacked page navigation
- Overview page
- Incidents page
- Investigation page
- Reports page
- Settings page
- Database connection
- Application status bar

Later steps will add:
- KPI cards
- Charts
- Incident tables
- Investigation controls
- PDF report integration
- Background live monitoring
"""

from __future__ import annotations

import sys
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from PySide6.QtCore import (
    Qt,
    QTimer,
    QThread,
    Signal,
)

from PySide6.QtGui import (
    QFont,
)

from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QPlainTextEdit,
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QLineEdit,
)

from matplotlib.backends.backend_qtagg import (
    FigureCanvasQTAgg as FigureCanvas,
)

from matplotlib.figure import Figure

from database.database import (
    DatabaseManager,
)
from reports.report_generator import IncidentReportGenerator



# ==========================================================
# Project Paths
# ==========================================================

PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent


# ==========================================================
# Application Style
# ==========================================================

APP_STYLESHEET = """
/* =========================================================
   GLOBAL
   ========================================================= */

QMainWindow {
    background-color: #f4f6f8;
}

QWidget {
    font-family: "Segoe UI";
    font-size: 13px;
    color: #1f2937;
}


/* =========================================================
   HEADER
   ========================================================= */

QFrame#headerFrame {
    background-color: #111827;
    border: none;
}

QLabel#appTitle {
    color: #ffffff;
    font-size: 20px;
    font-weight: 700;
}

QLabel#appSubtitle {
    color: #9ca3af;
    font-size: 11px;
}

QLabel#monitorStatusOffline {
    color: #fca5a5;
    background-color: #3f1d24;
    border: 1px solid #7f1d1d;
    border-radius: 12px;
    padding: 5px 12px;
    font-weight: 600;
}

QLabel#monitorStatusOnline {
    color: #86efac;
    background-color: #16351f;
    border: 1px solid #166534;
    border-radius: 12px;
    padding: 5px 12px;
    font-weight: 600;
}


/* =========================================================
   SIDEBAR
   ========================================================= */

QFrame#sidebarFrame {
    background-color: #1f2937;
    border: none;
}

QLabel#navigationTitle {
    color: #9ca3af;
    font-size: 10px;
    font-weight: 700;
    padding: 8px 14px;
}

QPushButton#navButton {
    background-color: transparent;
    color: #d1d5db;

    border: none;
    border-radius: 6px;

    text-align: left;

    padding: 11px 14px;

    font-size: 13px;
    font-weight: 500;
}

QPushButton#navButton:hover {
    background-color: #374151;
    color: #ffffff;
}

QPushButton#navButton:checked {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 600;
}


/* =========================================================
   CONTENT
   ========================================================= */

QFrame#contentFrame {
    background-color: #f4f6f8;
    border: none;
}

QLabel#pageTitle {
    color: #111827;
    font-size: 25px;
    font-weight: 700;
}

QLabel#pageSubtitle {
    color: #6b7280;
    font-size: 13px;
}


/* =========================================================
   PLACEHOLDER CARDS
   ========================================================= */

QFrame#placeholderCard {
    background-color: #ffffff;

    border: 1px solid #e5e7eb;
    border-radius: 10px;
}

QLabel#placeholderTitle {
    color: #111827;
    font-size: 16px;
    font-weight: 600;
}

QLabel#placeholderText {
    color: #6b7280;
    font-size: 12px;
}


/* =========================================================
   STATUS BAR
   ========================================================= */

QFrame#statusFrame {
    background-color: #ffffff;
    border-top: 1px solid #e5e7eb;
}

QLabel#statusText {
    color: #6b7280;
    font-size: 11px;
}

QLabel#databaseConnected {
    color: #15803d;
    font-size: 11px;
    font-weight: 600;
}

QLabel#databaseError {
    color: #b91c1c;
    font-size: 11px;
    font-weight: 600;
}
/* =========================================================
   DASHBOARD KPI CARDS
   ========================================================= */

QFrame#kpiCard {
    background-color: #ffffff;

    border: 1px solid #e5e7eb;
    border-radius: 10px;
}

QLabel#kpiLabel {
    color: #6b7280;

    font-size: 11px;
    font-weight: 700;
}

QLabel#kpiValue {
    color: #111827;

    font-size: 28px;
    font-weight: 700;
}

QLabel#criticalValue {
    color: #b91c1c;

    font-size: 28px;
    font-weight: 700;
}

QLabel#highValue {
    color: #c2410c;

    font-size: 28px;
    font-weight: 700;
}

QLabel#mediumValue {
    color: #a16207;

    font-size: 28px;
    font-weight: 700;
}

QLabel#lowValue {
    color: #15803d;

    font-size: 28px;
    font-weight: 700;
}

QLabel#openValue {
    color: #2563eb;

    font-size: 28px;
    font-weight: 700;
}


/* =========================================================
   DASHBOARD SECTIONS
   ========================================================= */

QFrame#dashboardSection {
    background-color: #ffffff;

    border: 1px solid #e5e7eb;
    border-radius: 10px;
}

QLabel#sectionTitle {
    color: #111827;

    font-size: 15px;
    font-weight: 700;
}

QLabel#sectionSubtitle {
    color: #6b7280;

    font-size: 11px;
}

QLabel#lastRefresh {
    color: #6b7280;

    font-size: 11px;
}


/* =========================================================
   INCIDENT TABLE
   ========================================================= */

QTableWidget {
    background-color: #ffffff;

    alternate-background-color: #f9fafb;

    border: none;

    gridline-color: #e5e7eb;

    selection-background-color: #dbeafe;
    selection-color: #111827;
}

QHeaderView::section {
    background-color: #f3f4f6;

    color: #374151;

    border: none;
    border-bottom: 1px solid #d1d5db;

    padding: 8px;

    font-size: 11px;
    font-weight: 700;
}
/* =========================================================
   INCIDENT MANAGEMENT
   ========================================================= */

QFrame#filterBar {
    background-color: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 10px;
}

QLineEdit,
QComboBox {
    background-color: #ffffff;
    color: #111827;

    border: 1px solid #d1d5db;
    border-radius: 6px;

    padding: 8px 10px;

    min-height: 20px;
}

QLineEdit:focus,
QComboBox:focus {
    border: 1px solid #2563eb;
}

QPushButton#primaryButton {
    background-color: #2563eb;
    color: #ffffff;

    border: none;
    border-radius: 6px;

    padding: 9px 16px;

    font-weight: 600;
}

QPushButton#primaryButton:hover {
    background-color: #1d4ed8;
}

QPushButton#secondaryButton {
    background-color: #ffffff;
    color: #374151;

    border: 1px solid #d1d5db;
    border-radius: 6px;

    padding: 8px 14px;

    font-weight: 600;
}

QPushButton#secondaryButton:hover {
    background-color: #f3f4f6;
}

QLabel#incidentCount {
    color: #4b5563;
    font-size: 12px;
    font-weight: 600;
}

QLabel#filterLabel {
    color: #374151;
    font-size: 11px;
    font-weight: 700;
}
"""


# ==========================================================
# Generic Placeholder Page
# ==========================================================

class PlaceholderPage(QWidget):
    """
    Base page used during Step 15.

    Later steps will replace the placeholder content
    with real dashboard widgets.
    """

    def __init__(
        self,
        title: str,
        subtitle: str,
        placeholder_title: str,
        placeholder_text: str,
        parent=None,
    ) -> None:

        super().__init__(
            parent
        )

        self._build_ui(
            title=title,
            subtitle=subtitle,
            placeholder_title=placeholder_title,
            placeholder_text=placeholder_text,
        )


    def _build_ui(
        self,
        *,
        title: str,
        subtitle: str,
        placeholder_title: str,
        placeholder_text: str,
    ) -> None:

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            28,
            24,
            28,
            24,
        )

        main_layout.setSpacing(
            8
        )

        # ==================================================
        # Page Title
        # ==================================================

        title_label = QLabel(
            title
        )

        title_label.setObjectName(
            "pageTitle"
        )

        subtitle_label = QLabel(
            subtitle
        )

        subtitle_label.setObjectName(
            "pageSubtitle"
        )

        subtitle_label.setWordWrap(
            True
        )

        main_layout.addWidget(
            title_label
        )

        main_layout.addWidget(
            subtitle_label
        )

        main_layout.addSpacing(
            16
        )

        # ==================================================
        # Placeholder Card
        # ==================================================

        card = QFrame()

        card.setObjectName(
            "placeholderCard"
        )

        card_layout = QVBoxLayout(
            card
        )

        card_layout.setContentsMargins(
            24,
            24,
            24,
            24,
        )

        card_layout.setSpacing(
            8
        )

        placeholder_title_label = QLabel(
            placeholder_title
        )

        placeholder_title_label.setObjectName(
            "placeholderTitle"
        )

        placeholder_text_label = QLabel(
            placeholder_text
        )

        placeholder_text_label.setObjectName(
            "placeholderText"
        )

        placeholder_text_label.setWordWrap(
            True
        )

        card_layout.addWidget(
            placeholder_title_label
        )

        card_layout.addWidget(
            placeholder_text_label
        )

        card_layout.addStretch()

        main_layout.addWidget(
            card,
            1,
        )


# ==========================================================
# Overview Page
# ==========================================================

# ==========================================================
# KPI Card
# ==========================================================

class KPICard(QFrame):
    """
    Small dashboard KPI card.
    """

    def __init__(
        self,
        title: str,
        value_object_name: str = "kpiValue",
        parent=None,
    ) -> None:

        super().__init__(
            parent
        )

        self.setObjectName(
            "kpiCard"
        )

        self.setMinimumHeight(
            105
        )

        self.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Fixed,
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            16,
            14,
            16,
            14,
        )

        layout.setSpacing(
            5
        )

        self.title_label = QLabel(
            title.upper()
        )

        self.title_label.setObjectName(
            "kpiLabel"
        )

        self.value_label = QLabel(
            "0"
        )

        self.value_label.setObjectName(
            value_object_name
        )

        layout.addWidget(
            self.title_label
        )

        layout.addWidget(
            self.value_label
        )

        layout.addStretch()


    def set_value(
        self,
        value: int,
    ) -> None:

        self.value_label.setText(
            str(
                value
            )
        )


# ==========================================================
# Matplotlib Chart Canvas
# ==========================================================

class DashboardChartCanvas(
    FigureCanvas
):
    """
    Reusable Matplotlib canvas for the PySide6 dashboard.
    """

    def __init__(
        self,
        parent=None,
    ) -> None:

        self.figure = Figure(
            figsize=(5, 3),
            tight_layout=True,
        )

        super().__init__(
            self.figure
        )

        self.setParent(
            parent
        )

        self.setMinimumHeight(
            260
        )

        self.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding,
        )


# ==========================================================
# Overview Page
# ==========================================================

class OverviewPage(QWidget):
    """
    Real Security Overview Dashboard.

    Reads incident information from SQLite and displays:

    - KPI cards
    - Severity distribution
    - Detection statistics
    - Recent incidents
    - Automatic refresh
    """

    REFRESH_INTERVAL_MS = 5000

    def __init__(
        self,
        database: DatabaseManager,
        parent=None,
    ) -> None:

        super().__init__(
            parent
        )

        self.database = database

        self._build_ui()

        self.refresh_dashboard()

        # ==================================================
        # Automatic Refresh
        # ==================================================

        self.refresh_timer = QTimer(
            self
        )

        self.refresh_timer.timeout.connect(
            self.refresh_dashboard
        )

        self.refresh_timer.start(
            self.REFRESH_INTERVAL_MS
        )


    # ======================================================
    # Build UI
    # ======================================================

    def _build_ui(
        self,
    ) -> None:

        outer_layout = QVBoxLayout(
            self
        )

        outer_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        # ==================================================
        # Scroll Area
        # ==================================================

        scroll_area = QScrollArea()

        scroll_area.setWidgetResizable(
            True
        )

        scroll_area.setFrameShape(
            QFrame.NoFrame
        )

        scroll_content = QWidget()

        self.main_layout = QVBoxLayout(
            scroll_content
        )

        self.main_layout.setContentsMargins(
            28,
            24,
            28,
            28,
        )

        self.main_layout.setSpacing(
            18
        )

        scroll_area.setWidget(
            scroll_content
        )

        outer_layout.addWidget(
            scroll_area
        )

        # ==================================================
        # Page Header
        # ==================================================

        header_layout = QHBoxLayout()

        header_text_layout = QVBoxLayout()

        header_text_layout.setSpacing(
            4
        )

        title = QLabel(
            "Security Overview"
        )

        title.setObjectName(
            "pageTitle"
        )

        subtitle = QLabel(
            "Real-time overview of security incidents, "
            "severity levels and detection activity."
        )

        subtitle.setObjectName(
            "pageSubtitle"
        )

        header_text_layout.addWidget(
            title
        )

        header_text_layout.addWidget(
            subtitle
        )

        header_layout.addLayout(
            header_text_layout
        )

        header_layout.addStretch()

        self.last_refresh_label = QLabel(
            "Last refresh: --"
        )

        self.last_refresh_label.setObjectName(
            "lastRefresh"
        )

        self.last_refresh_label.setAlignment(
            Qt.AlignRight | Qt.AlignVCenter
        )

        header_layout.addWidget(
            self.last_refresh_label
        )

        self.main_layout.addLayout(
            header_layout
        )

        # ==================================================
        # KPI Cards
        # ==================================================

        kpi_layout = QGridLayout()

        kpi_layout.setHorizontalSpacing(
            12
        )

        kpi_layout.setVerticalSpacing(
            12
        )

        self.total_card = KPICard(
            "Total Incidents",
            "kpiValue",
        )

        self.critical_card = KPICard(
            "Critical",
            "criticalValue",
        )

        self.high_card = KPICard(
            "High",
            "highValue",
        )

        self.medium_card = KPICard(
            "Medium",
            "mediumValue",
        )

        self.low_card = KPICard(
            "Low",
            "lowValue",
        )

        self.open_card = KPICard(
            "Open",
            "openValue",
        )

        cards = [
            self.total_card,
            self.critical_card,
            self.high_card,
            self.medium_card,
            self.low_card,
            self.open_card,
        ]

        for index, card in enumerate(
            cards
        ):

            kpi_layout.addWidget(
                card,
                0,
                index,
            )

            kpi_layout.setColumnStretch(
                index,
                1,
            )

        self.main_layout.addLayout(
            kpi_layout
        )

        # ==================================================
        # Charts
        # ==================================================

        charts_layout = QHBoxLayout()

        charts_layout.setSpacing(
            14
        )

        # Severity chart card

        severity_frame = QFrame()

        severity_frame.setObjectName(
            "dashboardSection"
        )

        severity_layout = QVBoxLayout(
            severity_frame
        )

        severity_layout.setContentsMargins(
            18,
            16,
            18,
            16,
        )

        severity_title = QLabel(
            "Severity Distribution"
        )

        severity_title.setObjectName(
            "sectionTitle"
        )

        severity_subtitle = QLabel(
            "Distribution of incidents by severity"
        )

        severity_subtitle.setObjectName(
            "sectionSubtitle"
        )

        self.severity_chart = (
            DashboardChartCanvas()
        )

        severity_layout.addWidget(
            severity_title
        )

        severity_layout.addWidget(
            severity_subtitle
        )

        severity_layout.addWidget(
            self.severity_chart,
            1,
        )

        # Detection chart card

        detection_frame = QFrame()

        detection_frame.setObjectName(
            "dashboardSection"
        )

        detection_layout = QVBoxLayout(
            detection_frame
        )

        detection_layout.setContentsMargins(
            18,
            16,
            18,
            16,
        )

        detection_title = QLabel(
            "Detection Statistics"
        )

        detection_title.setObjectName(
            "sectionTitle"
        )

        detection_subtitle = QLabel(
            "Most frequently detected security activities"
        )

        detection_subtitle.setObjectName(
            "sectionSubtitle"
        )

        self.detection_chart = (
            DashboardChartCanvas()
        )

        detection_layout.addWidget(
            detection_title
        )

        detection_layout.addWidget(
            detection_subtitle
        )

        detection_layout.addWidget(
            self.detection_chart,
            1,
        )

        charts_layout.addWidget(
            severity_frame,
            1,
        )

        charts_layout.addWidget(
            detection_frame,
            1,
        )

        self.main_layout.addLayout(
            charts_layout
        )

        # ==================================================
        # Recent Incidents
        # ==================================================

        incidents_frame = QFrame()

        incidents_frame.setObjectName(
            "dashboardSection"
        )

        incidents_layout = QVBoxLayout(
            incidents_frame
        )

        incidents_layout.setContentsMargins(
            18,
            16,
            18,
            16,
        )

        incidents_title = QLabel(
            "Recent Security Incidents"
        )

        incidents_title.setObjectName(
            "sectionTitle"
        )

        incidents_subtitle = QLabel(
            "Latest incidents stored by the "
            "Intelligent SOC Assistant"
        )

        incidents_subtitle.setObjectName(
            "sectionSubtitle"
        )

        self.incident_table = QTableWidget()

        self.incident_table.setColumnCount(
            8
        )

        self.incident_table.setHorizontalHeaderLabels(
            [
                "Incident ID",
                "Time",
                "Detection",
                "Source IP",
                "Host",
                "Severity",
                "Risk",
                "Status",
            ]
        )

        self.incident_table.setAlternatingRowColors(
            True
        )

        self.incident_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.incident_table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.incident_table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.incident_table.verticalHeader().setVisible(
            False
        )

        self.incident_table.setMinimumHeight(
            260
        )

        header = (
            self.incident_table
            .horizontalHeader()
        )

        header.setSectionResizeMode(
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            2,
            QHeaderView.Stretch,
        )

        incidents_layout.addWidget(
            incidents_title
        )

        incidents_layout.addWidget(
            incidents_subtitle
        )

        incidents_layout.addSpacing(
            5
        )

        incidents_layout.addWidget(
            self.incident_table
        )

        self.main_layout.addWidget(
            incidents_frame
        )


    # ======================================================
    # Load Incidents
    # ======================================================

    def _load_incidents(
        self,
    ) -> List[Dict[str, Any]]:
        """
        Load incidents from the real database.

        A high limit is used for dashboard statistics.
        """

        try:

            incidents = (
                self.database
                .get_recent_incidents(
                    limit=1000
                )
            )

            if incidents is None:

                return []

            return list(
                incidents
            )

        except Exception as error:

            print(
                "[DASHBOARD] Failed to load incidents:",
                error,
            )

            return []


    # ======================================================
    # Refresh Dashboard
    # ======================================================

    def refresh_dashboard(
        self,
    ) -> None:
        """
        Refresh all dashboard components.
        """

        incidents = (
            self._load_incidents()
        )

        self._update_kpi_cards(
            incidents
        )

        self._update_severity_chart(
            incidents
        )

        self._update_detection_chart(
            incidents
        )

        self._update_recent_incidents(
            incidents[:10]
        )

        self.last_refresh_label.setText(

            "Last refresh: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )


    # ======================================================
    # KPI Cards
    # ======================================================

    def _update_kpi_cards(
        self,
        incidents: List[
            Dict[str, Any]
        ],
    ) -> None:

        severity_counts = Counter()

        open_count = 0

        for incident in incidents:

            severity = str(
                incident.get(
                    "severity",
                    ""
                )
                or ""
            ).strip().upper()

            status = str(
                incident.get(
                    "status",
                    ""
                )
                or ""
            ).strip().upper()

            if severity:

                severity_counts[
                    severity
                ] += 1

            if status == "OPEN":

                open_count += 1

        self.total_card.set_value(
            len(
                incidents
            )
        )

        self.critical_card.set_value(
            severity_counts.get(
                "CRITICAL",
                0,
            )
        )

        self.high_card.set_value(
            severity_counts.get(
                "HIGH",
                0,
            )
        )

        self.medium_card.set_value(
            severity_counts.get(
                "MEDIUM",
                0,
            )
        )

        self.low_card.set_value(
            severity_counts.get(
                "LOW",
                0,
            )
        )

        self.open_card.set_value(
            open_count
        )


    # ======================================================
    # Severity Chart
    # ======================================================

    def _update_severity_chart(
        self,
        incidents: List[
            Dict[str, Any]
        ],
    ) -> None:

        figure = (
            self.severity_chart.figure
        )

        figure.clear()

        axis = figure.add_subplot(
            111
        )

        severity_order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
        ]

        severity_counts = Counter(

            str(
                incident.get(
                    "severity",
                    ""
                )
                or ""
            ).strip().upper()

            for incident in incidents
        )

        labels = []

        values = []

        for severity in severity_order:

            count = severity_counts.get(
                severity,
                0,
            )

            if count > 0:

                labels.append(
                    severity.title()
                )

                values.append(
                    count
                )

        if not values:

            axis.text(
                0.5,
                0.5,
                "No incident data available",
                horizontalalignment="center",
                verticalalignment="center",
                transform=axis.transAxes,
            )

            axis.set_axis_off()

        else:

            wedges, texts, autotexts = axis.pie(

                values,

                labels=labels,

                autopct="%1.0f%%",

                startangle=90,

                wedgeprops={
                    "width": 0.42,
                    "edgecolor": "white",
                },
            )

            axis.axis(
                "equal"
            )

        figure.patch.set_facecolor(
            "white"
        )

        self.severity_chart.draw_idle()


    # ======================================================
    # Detection Statistics
    # ======================================================

    def _update_detection_chart(
        self,
        incidents: List[
            Dict[str, Any]
        ],
    ) -> None:

        figure = (
            self.detection_chart.figure
        )

        figure.clear()

        axis = figure.add_subplot(
            111
        )

        detection_counts = Counter()

        for incident in incidents:

            detection = str(
                incident.get(
                    "detection_type",
                    ""
                )
                or "Unknown"
            ).strip()

            detection_counts[
                detection
            ] += 1

        most_common = (
            detection_counts
            .most_common(
                6
            )
        )

        if not most_common:

            axis.text(
                0.5,
                0.5,
                "No detection data available",
                horizontalalignment="center",
                verticalalignment="center",
                transform=axis.transAxes,
            )

            axis.set_axis_off()

        else:

            labels = [
                item[0]
                for item in most_common
            ]

            values = [
                item[1]
                for item in most_common
            ]

            # Shorten long labels for chart readability.

            display_labels = [

                (
                    label[:28] + "..."
                    if len(label) > 31
                    else label
                )

                for label in labels
            ]

            positions = list(
                range(
                    len(
                        display_labels
                    )
                )
            )

            axis.barh(
                positions,
                values,
            )

            axis.set_yticks(
                positions
            )

            axis.set_yticklabels(
                display_labels,
                fontsize=8,
            )

            axis.invert_yaxis()

            axis.set_xlabel(
                "Incidents",
                fontsize=8,
            )

            axis.tick_params(
                axis="x",
                labelsize=8,
            )

            axis.grid(
                axis="x",
                alpha=0.2,
            )

        figure.patch.set_facecolor(
            "white"
        )

        self.detection_chart.draw_idle()


    # ======================================================
    # Recent Incident Table
    # ======================================================

    def _update_recent_incidents(
        self,
        incidents: List[
            Dict[str, Any]
        ],
    ) -> None:

        self.incident_table.setRowCount(
            len(
                incidents
            )
        )

        for row, incident in enumerate(
            incidents
        ):

            values = [

                self._display_value(
                    incident.get(
                        "incident_id"
                    )
                ),

                self._format_timestamp(
                    incident.get(
                        "created_at"
                    )
                    or incident.get(
                        "last_seen"
                    )
                ),

                self._display_value(
                    incident.get(
                        "detection_type"
                    )
                ),

                self._display_value(
                    incident.get(
                        "source_ip"
                    )
                ),

                self._display_value(
                    incident.get(
                        "hostname"
                    )
                ),

                self._display_value(
                    incident.get(
                        "severity"
                    )
                ),

                self._display_value(
                    incident.get(
                        "risk_score"
                    )
                ),

                self._display_value(
                    incident.get(
                        "status"
                    )
                ),
            ]

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    value
                )

                item.setToolTip(
                    value
                )

                if column in {
                    5,
                    6,
                    7,
                }:

                    item.setTextAlignment(
                        Qt.AlignCenter
                    )

                self.incident_table.setItem(
                    row,
                    column,
                    item,
                )


    # ======================================================
    # Display Helpers
    # ======================================================

    @staticmethod
    def _display_value(
        value: Any,
    ) -> str:

        if value is None:

            return "-"

        text = str(
            value
        ).strip()

        if not text:

            return "-"

        return text


    @staticmethod
    def _format_timestamp(
        value: Any,
    ) -> str:

        if value is None:

            return "-"

        text = str(
            value
        ).strip()

        if not text:

            return "-"

        try:

            parsed = datetime.fromisoformat(

                text.replace(
                    "Z",
                    "+00:00",
                )
            )

            # Convert timezone-aware UTC timestamps
            # to the Windows machine's local timezone.

            if parsed.tzinfo is not None:

                parsed = (
                    parsed.astimezone()
                )

            return parsed.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:

            return text

# ==========================================================
# Incidents Page
# ==========================================================

# ==========================================================
# Incident Management Page
# ==========================================================

class IncidentsPage(QWidget):
    """
    Incident Management Page.

    Provides:
    - Real SQLite incident records
    - Search
    - Severity filter
    - Status filter
    - Detection type filter
    - Sortable table
    - Automatic refresh
    - Manual refresh
    """

    REFRESH_INTERVAL_MS = 5000

    def __init__(
        self,
        database: DatabaseManager,
        parent=None,
    ) -> None:

        super().__init__(
            parent
        )

        self.database = database

        # Complete data loaded from database.
        self.all_incidents: List[
            Dict[str, Any]
        ] = []

        # Data currently visible after filtering.
        self.filtered_incidents: List[
            Dict[str, Any]
        ] = []

        self._build_ui()

        self.refresh_incidents()

        # Automatic refresh every 5 seconds.
        self.refresh_timer = QTimer(
            self
        )

        self.refresh_timer.timeout.connect(
            self.refresh_incidents
        )

        self.refresh_timer.start(
            self.REFRESH_INTERVAL_MS
        )


    # ======================================================
    # Build UI
    # ======================================================

    def _build_ui(
        self,
    ) -> None:

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            28,
            24,
            28,
            24,
        )

        main_layout.setSpacing(
            16
        )

        # ==================================================
        # Header
        # ==================================================

        header_layout = QHBoxLayout()

        header_text_layout = QVBoxLayout()

        header_text_layout.setSpacing(
            4
        )

        title = QLabel(
            "Incident Management"
        )

        title.setObjectName(
            "pageTitle"
        )

        subtitle = QLabel(
            "Search, filter and manage detected "
            "security incidents."
        )

        subtitle.setObjectName(
            "pageSubtitle"
        )

        header_text_layout.addWidget(
            title
        )

        header_text_layout.addWidget(
            subtitle
        )

        header_layout.addLayout(
            header_text_layout
        )

        header_layout.addStretch()

        self.incident_count_label = QLabel(
            "0 incidents"
        )

        self.incident_count_label.setObjectName(
            "incidentCount"
        )

        header_layout.addWidget(
            self.incident_count_label
        )

        main_layout.addLayout(
            header_layout
        )

        # ==================================================
        # Filters
        # ==================================================

        filter_frame = QFrame()

        filter_frame.setObjectName(
            "filterBar"
        )

        filter_layout = QVBoxLayout(
            filter_frame
        )

        filter_layout.setContentsMargins(
            16,
            14,
            16,
            14,
        )

        filter_layout.setSpacing(
            10
        )

        filter_title = QLabel(
            "FILTER INCIDENTS"
        )

        filter_title.setObjectName(
            "filterLabel"
        )

        filter_layout.addWidget(
            filter_title
        )

        controls_layout = QHBoxLayout()

        controls_layout.setSpacing(
            10
        )

        # Search

        self.search_input = QLineEdit()

        self.search_input.setPlaceholderText(
            "Search Incident ID, detection, "
            "username, source IP or host..."
        )

        self.search_input.setClearButtonEnabled(
            True
        )

        self.search_input.textChanged.connect(
            self.apply_filters
        )

        controls_layout.addWidget(
            self.search_input,
            3,
        )

        # Severity

        self.severity_filter = QComboBox()

        self.severity_filter.addItems(
            [
                "All Severities",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
            ]
        )

        self.severity_filter.currentTextChanged.connect(
            self.apply_filters
        )

        controls_layout.addWidget(
            self.severity_filter,
            1,
        )

        # Status

        self.status_filter = QComboBox()

        self.status_filter.addItem(
            "All Statuses"
        )

        self.status_filter.currentTextChanged.connect(
            self.apply_filters
        )

        controls_layout.addWidget(
            self.status_filter,
            1,
        )

        # Detection Type

        self.detection_filter = QComboBox()

        self.detection_filter.addItem(
            "All Detections"
        )

        self.detection_filter.currentTextChanged.connect(
            self.apply_filters
        )

        controls_layout.addWidget(
            self.detection_filter,
            2,
        )

        # Clear Filters

        self.clear_filters_button = QPushButton(
            "Clear Filters"
        )

        self.clear_filters_button.setObjectName(
            "secondaryButton"
        )

        self.clear_filters_button.setCursor(
            Qt.PointingHandCursor
        )

        self.clear_filters_button.clicked.connect(
            self.clear_filters
        )

        controls_layout.addWidget(
            self.clear_filters_button
        )

        # Refresh

        self.refresh_button = QPushButton(
            "Refresh"
        )

        self.refresh_button.setObjectName(
            "primaryButton"
        )

        self.refresh_button.setCursor(
            Qt.PointingHandCursor
        )

        self.refresh_button.clicked.connect(
            self.refresh_incidents
        )

        controls_layout.addWidget(
            self.refresh_button
        )

        filter_layout.addLayout(
            controls_layout
        )

        main_layout.addWidget(
            filter_frame
        )

        # ==================================================
        # Incident Table Card
        # ==================================================

        table_frame = QFrame()

        table_frame.setObjectName(
            "dashboardSection"
        )

        table_layout = QVBoxLayout(
            table_frame
        )

        table_layout.setContentsMargins(
            16,
            16,
            16,
            16,
        )

        table_layout.setSpacing(
            8
        )

        table_header_layout = QHBoxLayout()

        table_title = QLabel(
            "Security Incident Records"
        )

        table_title.setObjectName(
            "sectionTitle"
        )

        self.last_refresh_label = QLabel(
            "Last refresh: --"
        )

        self.last_refresh_label.setObjectName(
            "lastRefresh"
        )

        table_header_layout.addWidget(
            table_title
        )

        table_header_layout.addStretch()

        table_header_layout.addWidget(
            self.last_refresh_label
        )

        table_layout.addLayout(
            table_header_layout
        )

        table_help = QLabel(
            "Select an incident to review it. "
            "Double-clicking will be connected to the "
            "Investigation workspace in Step 18."
        )

        table_help.setObjectName(
            "sectionSubtitle"
        )

        table_layout.addWidget(
            table_help
        )

        # ==================================================
        # Table
        # ==================================================

        self.incident_table = QTableWidget()

        self.incident_table.setColumnCount(
            11
        )

        self.incident_table.setHorizontalHeaderLabels(
            [
                "Incident ID",
                "Created",
                "Detection Type",
                "Category",
                "Source IP",
                "Username",
                "Host",
                "Severity",
                "Risk",
                "Confidence",
                "Status",
            ]
        )

        self.incident_table.setAlternatingRowColors(
            True
        )

        self.incident_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.incident_table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.incident_table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.incident_table.setSortingEnabled(
            True
        )

        self.incident_table.verticalHeader().setVisible(
            False
        )

        self.incident_table.verticalHeader().setDefaultSectionSize(
            38
        )

        header = (
            self.incident_table
            .horizontalHeader()
        )

        header.setSectionsClickable(
            True
        )

        header.setSortIndicatorShown(
            True
        )

        # Default sizing.
        header.setSectionResizeMode(
            QHeaderView.ResizeToContents
        )

        # Give detection type extra space.
        header.setSectionResizeMode(
            2,
            QHeaderView.Stretch,
        )

        self.incident_table.doubleClicked.connect(
            self._handle_double_click
        )

        table_layout.addWidget(
            self.incident_table,
            1,
        )

        main_layout.addWidget(
            table_frame,
            1,
        )


    # ======================================================
    # Database Loading
    # ======================================================

    def _load_incidents(
        self,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve incidents from SQLite.
        """

        try:

            incidents = (
                self.database
                .get_recent_incidents(
                    limit=1000
                )
            )

            if incidents is None:

                return []

            return list(
                incidents
            )

        except Exception as error:

            print(
                "[INCIDENTS] Failed to load incidents:",
                error,
            )

            return []


    # ======================================================
    # Refresh
    # ======================================================

    def refresh_incidents(
        self,
    ) -> None:
        """
        Reload incidents from SQLite and refresh filters.
        """

        # Remember current filter choices so that
        # automatic refresh does not reset the user.

        current_status = (
            self.status_filter.currentText()
        )

        current_detection = (
            self.detection_filter.currentText()
        )

        self.all_incidents = (
            self._load_incidents()
        )

        self._populate_dynamic_filters(
            current_status=current_status,
            current_detection=current_detection,
        )

        self.apply_filters()

        self.last_refresh_label.setText(
            "Last refresh: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )


    # ======================================================
    # Dynamic Filter Options
    # ======================================================

    def _populate_dynamic_filters(
        self,
        current_status: str,
        current_detection: str,
    ) -> None:

        statuses = sorted(
            {
                str(
                    incident.get(
                        "status",
                        ""
                    )
                    or ""
                ).strip()

                for incident
                in self.all_incidents

                if str(
                    incident.get(
                        "status",
                        ""
                    )
                    or ""
                ).strip()
            }
        )

        detections = sorted(
            {
                str(
                    incident.get(
                        "detection_type",
                        ""
                    )
                    or ""
                ).strip()

                for incident
                in self.all_incidents

                if str(
                    incident.get(
                        "detection_type",
                        ""
                    )
                    or ""
                ).strip()
            }
        )

        # Prevent signals firing repeatedly while rebuilding.

        self.status_filter.blockSignals(
            True
        )

        self.detection_filter.blockSignals(
            True
        )

        # Statuses

        self.status_filter.clear()

        self.status_filter.addItem(
            "All Statuses"
        )

        self.status_filter.addItems(
            statuses
        )

        status_index = (
            self.status_filter.findText(
                current_status
            )
        )

        if status_index >= 0:

            self.status_filter.setCurrentIndex(
                status_index
            )

        # Detections

        self.detection_filter.clear()

        self.detection_filter.addItem(
            "All Detections"
        )

        self.detection_filter.addItems(
            detections
        )

        detection_index = (
            self.detection_filter.findText(
                current_detection
            )
        )

        if detection_index >= 0:

            self.detection_filter.setCurrentIndex(
                detection_index
            )

        self.status_filter.blockSignals(
            False
        )

        self.detection_filter.blockSignals(
            False
        )


    # ======================================================
    # Apply Filters
    # ======================================================

    def apply_filters(
        self,
        *_args,
    ) -> None:
        """
        Apply search and combo-box filters.
        """

        search_text = (
            self.search_input
            .text()
            .strip()
            .lower()
        )

        severity_choice = (
            self.severity_filter
            .currentText()
            .strip()
            .upper()
        )

        status_choice = (
            self.status_filter
            .currentText()
            .strip()
        )

        detection_choice = (
            self.detection_filter
            .currentText()
            .strip()
        )

        filtered = []

        for incident in self.all_incidents:

            severity = str(
                incident.get(
                    "severity",
                    ""
                )
                or ""
            ).strip().upper()

            status = str(
                incident.get(
                    "status",
                    ""
                )
                or ""
            ).strip()

            detection = str(
                incident.get(
                    "detection_type",
                    ""
                )
                or ""
            ).strip()

            # ==============================================
            # Severity Filter
            # ==============================================

            if (
                severity_choice
                != "ALL SEVERITIES"
                and severity
                != severity_choice
            ):

                continue

            # ==============================================
            # Status Filter
            # ==============================================

            if (
                status_choice
                != "All Statuses"
                and status
                != status_choice
            ):

                continue

            # ==============================================
            # Detection Filter
            # ==============================================

            if (
                detection_choice
                != "All Detections"
                and detection
                != detection_choice
            ):

                continue

            # ==============================================
            # Search
            # ==============================================

            if search_text:

                searchable_values = [

                    incident.get(
                        "incident_id"
                    ),

                    incident.get(
                        "detection_type"
                    ),

                    incident.get(
                        "detection_category"
                    ),

                    incident.get(
                        "source_ip"
                    ),

                    incident.get(
                        "username"
                    ),

                    incident.get(
                        "hostname"
                    ),

                    incident.get(
                        "severity"
                    ),

                    incident.get(
                        "status"
                    ),
                ]

                searchable_text = " ".join(

                    str(
                        value
                    )

                    for value
                    in searchable_values

                    if value is not None
                ).lower()

                if (
                    search_text
                    not in searchable_text
                ):

                    continue

            filtered.append(
                incident
            )

        self.filtered_incidents = filtered

        self._populate_table(
            filtered
        )

        self._update_incident_count()


    # ======================================================
    # Populate Table
    # ======================================================

    def _populate_table(
        self,
        incidents: List[
            Dict[str, Any]
        ],
    ) -> None:

        # Disable sorting while inserting rows.
        # Otherwise Qt may move rows during population.

        sorting_enabled = (
            self.incident_table
            .isSortingEnabled()
        )

        self.incident_table.setSortingEnabled(
            False
        )

        self.incident_table.clearContents()

        self.incident_table.setRowCount(
            len(
                incidents
            )
        )

        for row, incident in enumerate(
            incidents
        ):

            values = [

                self._display_value(
                    incident.get(
                        "incident_id"
                    )
                ),

                self._format_timestamp(
                    incident.get(
                        "created_at"
                    )
                    or incident.get(
                        "last_seen"
                    )
                ),

                self._display_value(
                    incident.get(
                        "detection_type"
                    )
                ),

                self._display_value(
                    incident.get(
                        "detection_category"
                    )
                ),

                self._display_value(
                    incident.get(
                        "source_ip"
                    )
                ),

                self._display_value(
                    incident.get(
                        "username"
                    )
                ),

                self._display_value(
                    incident.get(
                        "hostname"
                    )
                ),

                self._display_value(
                    incident.get(
                        "severity"
                    )
                ),

                self._display_value(
                    incident.get(
                        "risk_score"
                    )
                ),

                self._display_value(
                    incident.get(
                        "confidence"
                    )
                ),

                self._display_value(
                    incident.get(
                        "status"
                    )
                ),
            ]

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    value
                )

                item.setToolTip(
                    value
                )

                # Store the real Incident ID in every row's
                # first column for Step 18 investigation.

                if column == 0:

                    item.setData(
                        Qt.UserRole,
                        incident.get(
                            "incident_id"
                        ),
                    )

                if column in {
                    7,
                    8,
                    9,
                    10,
                }:

                    item.setTextAlignment(
                        Qt.AlignCenter
                    )

                self.incident_table.setItem(
                    row,
                    column,
                    item,
                )

        self.incident_table.setSortingEnabled(
            sorting_enabled
        )


    # ======================================================
    # Incident Count
    # ======================================================

    def _update_incident_count(
        self,
    ) -> None:

        visible_count = len(
            self.filtered_incidents
        )

        total_count = len(
            self.all_incidents
        )

        if visible_count == total_count:

            text = (
                f"{total_count} incident"
                if total_count == 1
                else f"{total_count} incidents"
            )

        else:

            text = (
                f"Showing {visible_count} "
                f"of {total_count} incidents"
            )

        self.incident_count_label.setText(
            text
        )


    # ======================================================
    # Clear Filters
    # ======================================================

    def clear_filters(
        self,
    ) -> None:

        self.search_input.clear()

        self.severity_filter.setCurrentIndex(
            0
        )

        self.status_filter.setCurrentIndex(
            0
        )

        self.detection_filter.setCurrentIndex(
            0
        )

        self.apply_filters()


    # ======================================================
    # Selected Incident
    # ======================================================

    def get_selected_incident_id(
        self,
    ) -> str | None:
        """
        Return selected Incident ID.
        """

        selected_rows = (
            self.incident_table
            .selectionModel()
            .selectedRows()
        )

        if not selected_rows:

            return None

        row = (
            selected_rows[0]
            .row()
        )

        item = (
            self.incident_table
            .item(
                row,
                0,
            )
        )

        if item is None:

            return None

        incident_id = item.data(
            Qt.UserRole
        )

        if not incident_id:

            incident_id = item.text()

        return str(
            incident_id
        )


    # ======================================================
    # Double Click
    # ======================================================

    def _handle_double_click(
        self,
        _index,
    ) -> None:

        incident_id = (
            self.get_selected_incident_id()
        )

        if not incident_id:
            return

        main_window = self.window()

        if not isinstance(
            main_window,
            QMainWindow,
        ):
            return

        investigation_page = (
            main_window.pages.get(
                "investigation"
            )
        )

        if investigation_page is None:
            return

        investigation_page.load_incident(
            incident_id
        )

        main_window.show_page(
            "investigation"
        )

    # ======================================================
    # Helpers
    # ======================================================

    @staticmethod
    def _display_value(
        value: Any,
    ) -> str:

        if value is None:

            return "-"

        text = str(
            value
        ).strip()

        if not text:

            return "-"

        return text


    @staticmethod
    def _format_timestamp(
        value: Any,
    ) -> str:

        if value is None:

            return "-"

        text = str(
            value
        ).strip()

        if not text:

            return "-"

        try:

            parsed = datetime.fromisoformat(

                text.replace(
                    "Z",
                    "+00:00",
                )
            )

            if parsed.tzinfo is not None:

                parsed = (
                    parsed.astimezone()
                )

            return parsed.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:

            return text

# ==========================================================
# Investigation Page
# ==========================================================

class InvestigationPage(QWidget):
    
    def __init__(
        self,
        database: DatabaseManager,
        parent=None,
    ) -> None:

        super().__init__(parent)

        self.database = database
        self.current_incident_id = None
        self.current_incident = None

        self._build_ui()


    def _build_ui(self) -> None:

        outer_layout = QVBoxLayout(self)

        outer_layout.setContentsMargins(
            0, 0, 0, 0
        )

        scroll = QScrollArea()

        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()

        layout = QVBoxLayout(content)

        layout.setContentsMargins(
            28, 24, 28, 28
        )

        layout.setSpacing(16)

        # ==========================================
        # Header
        # ==========================================

        header = QHBoxLayout()

        title_area = QVBoxLayout()

        title = QLabel(
            "Incident Investigation"
        )

        title.setObjectName(
            "pageTitle"
        )

        subtitle = QLabel(
            "Review detection evidence, risk, MITRE ATT&CK "
            "mapping and recommended response actions."
        )

        subtitle.setObjectName(
            "pageSubtitle"
        )

        title_area.addWidget(title)
        title_area.addWidget(subtitle)

        header.addLayout(title_area)
        header.addStretch()

        self.generate_report_button = QPushButton(
            "Generate PDF Report"
        )

        self.generate_report_button.setObjectName(
            "primaryButton"
        )

        self.generate_report_button.setEnabled(False)

        self.generate_report_button.clicked.connect(
            self.generate_current_report
        )

        header.addWidget(
            self.generate_report_button
        )

        layout.addLayout(header)

        # ==========================================
        # Empty state
        # ==========================================

        self.empty_label = QLabel(
            "Select or double-click an incident from "
            "Incident Management to begin investigation."
        )

        self.empty_label.setObjectName(
            "sectionSubtitle"
        )

        self.empty_label.setAlignment(
            Qt.AlignCenter
        )

        self.empty_label.setMinimumHeight(80)

        layout.addWidget(
            self.empty_label
        )

        # ==========================================
        # Incident summary
        # ==========================================

        summary = QFrame()

        summary.setObjectName(
            "dashboardSection"
        )

        summary_layout = QGridLayout(summary)

        summary_layout.setContentsMargins(
            18, 18, 18, 18
        )

        self.detail_labels = {}

        fields = [
            ("incident_id", "Incident ID"),
            ("detection_type", "Detection"),
            ("detection_category", "Category"),
            ("severity", "Severity"),
            ("risk_score", "Risk Score"),
            ("confidence", "Confidence"),
            ("status", "Status"),
            ("source_ip", "Source IP"),
            ("destination_ip", "Destination IP"),
            ("username", "Username"),
            ("hostname", "Hostname"),
            ("host_ip", "Host IP"),
            ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"),
        ]

        for index, (key, label_text) in enumerate(fields):

            row = index // 2
            column = (index % 2) * 2

            label = QLabel(
                label_text + ":"
            )

            label.setObjectName(
                "filterLabel"
            )

            value = QLabel("-")

            value.setWordWrap(True)

            self.detail_labels[key] = value

            summary_layout.addWidget(
                label,
                row,
                column,
            )

            summary_layout.addWidget(
                value,
                row,
                column + 1,
            )

        layout.addWidget(summary)

        # ==========================================
        # Description
        # ==========================================

        self.description_box = self._create_text_section(
            "Detection Description"
        )

        layout.addWidget(
            self.description_box["frame"]
        )

        # ==========================================
        # Evidence
        # ==========================================

        self.evidence_box = self._create_text_section(
            "Evidence"
        )

        layout.addWidget(
            self.evidence_box["frame"]
        )

        # ==========================================
        # MITRE
        # ==========================================

        self.mitre_box = self._create_text_section(
            "MITRE ATT&CK Mapping"
        )

        layout.addWidget(
            self.mitre_box["frame"]
        )

        # ==========================================
        # Severity reasoning
        # ==========================================

        self.severity_box = self._create_text_section(
            "Severity & Risk Assessment"
        )

        layout.addWidget(
            self.severity_box["frame"]
        )

        # ==========================================
        # Recommendations
        # ==========================================

        self.recommendation_box = self._create_text_section(
            "Recommended SOC Actions"
        )

        layout.addWidget(
            self.recommendation_box["frame"]
        )

        scroll.setWidget(content)

        outer_layout.addWidget(scroll)


    def _create_text_section(
        self,
        title: str,
    ):

        frame = QFrame()

        frame.setObjectName(
            "dashboardSection"
        )

        layout = QVBoxLayout(frame)

        layout.setContentsMargins(
            18, 16, 18, 16
        )

        title_label = QLabel(title)

        title_label.setObjectName(
            "sectionTitle"
        )

        text = QPlainTextEdit()

        text.setReadOnly(True)

        text.setMinimumHeight(120)

        layout.addWidget(title_label)
        layout.addWidget(text)

        return {
            "frame": frame,
            "text": text,
        }


    def load_incident(
        self,
        incident_id: str,
    ) -> None:

        try:

            incident = self.database.get_incident(
                incident_id
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Investigation Error",
                f"Could not load incident.\n\n{error}",
            )

            return

        if not incident:

            QMessageBox.warning(
                self,
                "Incident Not Found",
                f"Incident {incident_id} was not found.",
            )

            return

        self.current_incident_id = incident_id
        self.current_incident = incident

        self.empty_label.hide()

        self.generate_report_button.setEnabled(
            True
        )

        for key, label in self.detail_labels.items():

            label.setText(
                self._display(
                    incident.get(key)
                )
            )

        self.description_box["text"].setPlainText(
            self._display(
                incident.get("description")
            )
        )

        self.evidence_box["text"].setPlainText(
            self._format_complex(
                incident.get("evidence")
            )
        )

        mitre_text = self._build_mitre_text(
            incident
        )

        self.mitre_box["text"].setPlainText(
            mitre_text
        )

        severity_text = self._build_severity_text(
            incident
        )

        self.severity_box["text"].setPlainText(
            severity_text
        )

        self.recommendation_box["text"].setPlainText(
            self._format_complex(
                incident.get("recommendations")
            )
        )


    @staticmethod
    def _display(value):

        if value is None:
            return "-"

        text = str(value).strip()

        return text if text else "-"


    @staticmethod
    def _format_complex(value):

        if value is None:
            return "-"

        if isinstance(value, list):

            return "\n".join(
                f"• {item}"
                for item in value
            )

        if isinstance(value, dict):

            return "\n".join(
                f"{key}: {item}"
                for key, item in value.items()
            )

        text = str(value).strip()

        if not text:
            return "-"

        # Handle JSON stored as TEXT in SQLite.

        try:

            parsed = json.loads(text)

            if isinstance(parsed, list):

                return "\n".join(
                    f"• {item}"
                    for item in parsed
                )

            if isinstance(parsed, dict):

                return "\n".join(
                    f"{key}: {item}"
                    for key, item in parsed.items()
                )

        except Exception:
            pass

        return text


    def _build_mitre_text(
        self,
        incident,
    ):

        values = []

        mappings = [
            ("MITRE Tactic", "mitre_tactic"),
            ("MITRE Technique", "mitre_technique_name"),
            ("Technique ID", "mitre_technique_id"),
        ]

        for label, key in mappings:

            value = incident.get(key)

            if value:

                values.append(
                    f"{label}: {value}"
                )

        # Some schemas store all MITRE data together.

        if not values:

            combined = (
                incident.get("mitre_mapping")
                or incident.get("mitre")
            )

            return self._format_complex(
                combined
            )

        return "\n".join(values)


    def _build_severity_text(
        self,
        incident,
    ):

        values = [
            f"Severity: {self._display(incident.get('severity'))}",
            f"Risk Score: {self._display(incident.get('risk_score'))}",
            f"Confidence: {self._display(incident.get('confidence'))}",
        ]

        reasons = (
            incident.get("severity_reasons")
            or incident.get("risk_reasons")
        )

        if reasons:

            values.append("")
            values.append(
                self._format_complex(reasons)
            )

        return "\n".join(values)


    def generate_current_report(
        self,
    ) -> None:

        if not self.current_incident_id:

            QMessageBox.warning(
                self,
                "No Incident Selected",
                "Select an incident first.",
            )

            return

        try:

            generator = IncidentReportGenerator()

            report_path = generator.generate_report(
                self.current_incident_id
            )

            QMessageBox.information(
                self,
                "Report Generated",
                "PDF report generated successfully.\n\n"
                f"{report_path}",
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Report Generation Error",
                str(error),
            )

# ==========================================================
# Reports Page
# ==========================================================

class ReportsPage(QWidget):
    
    def __init__(
        self,
        database: DatabaseManager,
        parent=None,
    ):
        super().__init__(parent)

        self.database = database
        self.report_generator = IncidentReportGenerator()

        self._build_ui()
        self.refresh_incidents()


    def _build_ui(self):

        main_layout = QVBoxLayout(self)

        main_layout.setContentsMargins(
            38, 32, 38, 32
        )

        main_layout.setSpacing(20)

        # ------------------------------------------------------
        # Header
        # ------------------------------------------------------

        title = QLabel(
            "Incident Reports"
        )

        title.setObjectName(
            "pageTitle"
        )

        subtitle = QLabel(
            "Generate and manage professional PDF "
            "security incident reports."
        )

        subtitle.setObjectName(
            "pageSubtitle"
        )

        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        # ------------------------------------------------------
        # Report Center
        # ------------------------------------------------------

        report_card = QFrame()

        report_card.setObjectName(
            "dashboardSection"
        )

        card_layout = QVBoxLayout(
            report_card
        )

        card_layout.setContentsMargins(
            28, 26, 28, 26
        )

        card_layout.setSpacing(18)

        heading = QLabel(
            "PDF Report Center"
        )

        heading.setObjectName(
            "sectionTitle"
        )

        description = QLabel(
            "Select a detected security incident "
            "and generate its complete PDF investigation report."
        )

        description.setWordWrap(True)

        description.setObjectName(
            "sectionSubtitle"
        )

        card_layout.addWidget(heading)
        card_layout.addWidget(description)

        # Incident selector

        selector_label = QLabel(
            "Select Incident"
        )

        selector_label.setObjectName(
            "filterLabel"
        )

        self.incident_combo = QComboBox()

        self.incident_combo.setMinimumHeight(
            44
        )

        card_layout.addWidget(
            selector_label
        )

        card_layout.addWidget(
            self.incident_combo
        )

        # Buttons

        button_layout = QHBoxLayout()

        self.refresh_button = QPushButton(
            "Refresh Incidents"
        )

        self.refresh_button.setMinimumHeight(
            44
        )

        self.refresh_button.clicked.connect(
            self.refresh_incidents
        )

        self.generate_button = QPushButton(
            "Generate PDF Report"
        )

        self.generate_button.setMinimumHeight(
            44
        )

        self.generate_button.setObjectName(
            "primaryButton"
        )

        self.generate_button.clicked.connect(
            self.generate_report
        )

        self.open_folder_button = QPushButton(
            "Open Reports Folder"
        )

        self.open_folder_button.setMinimumHeight(
            44
        )

        self.open_folder_button.clicked.connect(
            self.open_reports_folder
        )

        button_layout.addWidget(
            self.refresh_button
        )

        button_layout.addWidget(
            self.generate_button
        )

        button_layout.addWidget(
            self.open_folder_button
        )

        button_layout.addStretch()

        card_layout.addLayout(
            button_layout
        )

        # Status

        self.status_label = QLabel(
            "Ready."
        )

        self.status_label.setWordWrap(
            True
        )

        self.status_label.setObjectName(
            "sectionSubtitle"
        )

        card_layout.addWidget(
            self.status_label
        )

        main_layout.addWidget(
            report_card
        )

        main_layout.addStretch()


    def refresh_incidents(self):

        current_incident = (
            self.incident_combo.currentData()
        )

        self.incident_combo.clear()

        try:

            incidents = (
                self.database.get_recent_incidents(
                    limit=1000
                )
                or []
            )

        except Exception as error:

            self.status_label.setText(
                f"Unable to load incidents: {error}"
            )

            self.generate_button.setEnabled(
                False
            )

            return

        for incident in incidents:

            incident_id = incident.get(
                "incident_id"
            )

            if not incident_id:
                continue

            severity = (
                incident.get("severity")
                or "Unknown"
            )

            detection = (
                incident.get("detection_type")
                or incident.get("attack_type")
                or "Security Incident"
            )

            display_text = (
                f"{incident_id}  |  "
                f"{severity}  |  "
                f"{detection}"
            )

            self.incident_combo.addItem(
                display_text,
                incident_id,
            )

        if current_incident:

            index = (
                self.incident_combo.findData(
                    current_incident
                )
            )

            if index >= 0:

                self.incident_combo.setCurrentIndex(
                    index
                )

        count = self.incident_combo.count()

        self.generate_button.setEnabled(
            count > 0
        )

        if count:

            self.status_label.setText(
                f"{count} incident(s) available for reporting."
            )

        else:

            self.status_label.setText(
                "No incidents are currently available."
            )


    def generate_report(self):

        incident_id = (
            self.incident_combo.currentData()
        )

        if not incident_id:

            QMessageBox.warning(
                self,
                "No Incident Selected",
                "Select an incident before generating a report.",
            )

            return

        try:

            report_path = (
                self.report_generator.generate_report(
                    incident_id
                )
            )

            self.status_label.setText(
                f"Latest report: {report_path}"
            )

            QMessageBox.information(
                self,
                "Report Generated",
                "PDF report generated successfully.\n\n"
                f"{report_path}",
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Report Generation Error",
                str(error),
            )


    def open_reports_folder(self):

        reports_folder = (
            PROJECT_ROOT
            / "reports"
            / "generated"
        )

        reports_folder.mkdir(
            parents=True,
            exist_ok=True
        )

        try:

            os.startfile(
                str(reports_folder)
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Open Reports Folder",
                str(error),
            )

# ==========================================================
# Settings Page
# ==========================================================

class SettingsPage(QWidget):
    
    def __init__(
        self,
        project_root,
        parent=None,
    ):
        super().__init__(parent)

        self.project_root = Path(
            project_root
        )

        self._build_ui()


    def _build_ui(self):

        layout = QVBoxLayout(self)

        layout.setContentsMargins(
            38,
            32,
            38,
            32,
        )

        layout.setSpacing(16)

        title = QLabel(
            "Settings"
        )

        title.setObjectName(
            "pageTitle"
        )

        subtitle = QLabel(
            "Application configuration and system information."
        )

        subtitle.setObjectName(
            "pageSubtitle"
        )

        layout.addWidget(title)
        layout.addWidget(subtitle)

        section = QFrame()

        section.setObjectName(
            "dashboardSection"
        )

        section_layout = QVBoxLayout(
            section
        )

        section_layout.setContentsMargins(
            24,
            24,
            24,
            24,
        )

        heading = QLabel(
            "Intelligent SOC Assistant"
        )

        heading.setObjectName(
            "sectionTitle"
        )

        project_label = QLabel(
            f"Project Directory:\n{self.project_root}"
        )

        project_label.setWordWrap(
            True
        )

        monitoring_info = QLabel(
            "Live monitoring can be controlled using "
            "the Start Monitoring and Stop Monitoring "
            "buttons in the application header."
        )

        monitoring_info.setWordWrap(
            True
        )

        section_layout.addWidget(
            heading
        )

        section_layout.addSpacing(8)

        section_layout.addWidget(
            project_label
        )

        section_layout.addSpacing(12)

        section_layout.addWidget(
            monitoring_info
        )

        layout.addWidget(
            section
        )

        layout.addStretch()
        # ==========================================================
# Background Live Monitor Worker
# ==========================================================

class MonitorWorker(QThread):
    """
    Runs the existing Windows Event Monitor in a background
    subprocess so the PySide6 desktop application remains
    responsive while live monitoring is active.
    """

    status_changed = Signal(bool, str)
    output_received = Signal(str)
    monitor_stopped = Signal()


    def __init__(
        self,
        project_root,
        parent=None,
    ):
        super().__init__(parent)

        self.project_root = Path(project_root)

        self.process = None

        self._stop_requested = False


    def run(self):
        """
        Start windows_event_monitor as a background subprocess.
        """

        self._stop_requested = False

        try:

            command = [
                sys.executable,
                "-u",
                "-m",
                "live_monitor.windows_event_monitor",
            ]

            creation_flags = 0

            if sys.platform == "win32":

                creation_flags = getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0,
                )

            self.process = subprocess.Popen(

                command,

                cwd=str(
                    self.project_root
                ),

                stdout=subprocess.PIPE,

                stderr=subprocess.STDOUT,

                text=True,

                bufsize=1,

                creationflags=creation_flags,
            )

            # --------------------------------------------------
            # Monitor successfully started
            # --------------------------------------------------

            self.status_changed.emit(
                True,
                "Monitoring Active",
            )

            # --------------------------------------------------
            # Read monitor output
            # --------------------------------------------------

            if self.process.stdout is not None:

                while not self._stop_requested:

                    line = (
                        self.process.stdout.readline()
                    )

                    if line:

                        self.output_received.emit(
                            line.rstrip()
                        )

                    # Process ended unexpectedly or normally.

                    if (
                        self.process.poll()
                        is not None
                    ):
                        break

            # --------------------------------------------------
            # Stop requested
            # --------------------------------------------------

            if (
                self._stop_requested
                and self.process is not None
                and self.process.poll() is None
            ):

                self.process.terminate()

                try:

                    self.process.wait(
                        timeout=5
                    )

                except subprocess.TimeoutExpired:

                    self.process.kill()

                    self.process.wait(
                        timeout=5
                    )

        except Exception as error:

            self.output_received.emit(
                f"[MONITOR ERROR] {error}"
            )

        finally:

            self.process = None

            self.status_changed.emit(
                False,
                "Monitoring Stopped",
            )

            self.monitor_stopped.emit()


    def stop_monitoring(self):
        """
        Request graceful shutdown of the monitor process.
        """

        self._stop_requested = True

        if (
            self.process is not None
            and self.process.poll() is None
        ):

            try:

                self.process.terminate()

            except Exception as error:

                self.output_received.emit(
                    f"[STOP ERROR] {error}"
                )


# ==========================================================
# Main Window
# ==========================================================

class MainWindow(
    QMainWindow
):
    """
    Main desktop application window.
    """

    def __init__(
        self,
    ) -> None:

        super().__init__()

        # ==================================================
        # Database
        # ==================================================

        self.database = (
            DatabaseManager()
        )

        self.database_connected = False
        self.monitor_worker = None

        # ==================================================
        # Navigation
        # ==================================================

        self.nav_buttons: Dict[
            str,
            QPushButton
        ] = {}

        # ==================================================
        # Window
        # ==================================================

        self.setWindowTitle(
            "Intelligent SOC Assistant"
        )

        self.setMinimumSize(
            1100,
            700,
        )

        self.resize(
            1400,
            850,
        )

        # ==================================================
        # Build
        # ==================================================

        self._initialize_database()

        self._build_ui()

        self._apply_styles()

        self.show_page(
            "overview"
        )


    # ======================================================
    # Database Initialization
    # ======================================================

    def _initialize_database(
        self,
    ) -> None:

        try:

            self.database.initialize_database()

            self.database_connected = True

        except Exception as error:

            self.database_connected = False

            QMessageBox.critical(

                self,

                "Database Error",

                (
                    "The Intelligent SOC Assistant "
                    "could not initialize its database."
                    "\n\n"
                    f"Error:\n{error}"
                ),
            )


    # ======================================================
    # Build Main UI
    # ======================================================

    def _build_ui(
        self,
    ) -> None:

        central_widget = QWidget()

        self.setCentralWidget(
            central_widget
        )

        root_layout = QVBoxLayout(
            central_widget
        )

        root_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        root_layout.setSpacing(
            0
        )

        # Header

        root_layout.addWidget(
            self._create_header()
        )

        # Main body

        body_widget = QWidget()

        body_layout = QHBoxLayout(
            body_widget
        )

        body_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        body_layout.setSpacing(
            0
        )

        body_layout.addWidget(
            self._create_sidebar()
        )

        body_layout.addWidget(
            self._create_content_area(),
            1,
        )

        root_layout.addWidget(
            body_widget,
            1,
        )

        # Bottom status

        root_layout.addWidget(
            self._create_status_bar()
        )


    # ======================================================
    # Header
    # ======================================================

    def _create_header(
        self,
    ) -> QFrame:

        header = QFrame()

        header.setObjectName(
            "headerFrame"
        )

        header.setFixedHeight(
            72
        )

        layout = QHBoxLayout(
            header
        )

        layout.setContentsMargins(
            22,
            10,
            22,
            10,
        )

        # ==================================================
        # Title Area
        # ==================================================

        title_layout = QVBoxLayout()

        title_layout.setSpacing(
            1
        )

        app_title = QLabel(
            "Intelligent SOC Assistant"
        )

        app_title.setObjectName(
            "appTitle"
        )

        app_subtitle = QLabel(
            "Security Operations & Incident Analysis"
        )

        app_subtitle.setObjectName(
            "appSubtitle"
        )

        title_layout.addWidget(
            app_title
        )

        title_layout.addWidget(
            app_subtitle
        )

        layout.addLayout(
            title_layout
        )

        layout.addStretch()
        
        
        # ==========================================================
# Live Monitoring Controls
# ==========================================================

        self.start_monitor_button = QPushButton(
    "Start Monitoring"
)

        self.start_monitor_button.setObjectName(
    "primaryButton"
)

        self.start_monitor_button.setCursor(
    Qt.PointingHandCursor
)

        self.start_monitor_button.clicked.connect(
    self.start_monitoring
)

        layout.addWidget(
    self.start_monitor_button
)


        self.stop_monitor_button = QPushButton(
    "Stop Monitoring"
)

        self.stop_monitor_button.setObjectName(
    "secondaryButton"
)

        self.stop_monitor_button.setCursor(
    Qt.PointingHandCursor
)

        self.stop_monitor_button.setEnabled(
    False
)

        self.stop_monitor_button.clicked.connect(
    self.stop_monitoring
)

        layout.addWidget(
    self.stop_monitor_button
)

        layout.addSpacing(
    10
)
        
        
    

        # ==================================================
        # Monitoring Status
        # ==================================================
        
        self.monitor_status_label = QLabel(
            "● MONITORING STOPPED"
        )

        self.monitor_status_label.setObjectName(
            "monitorStatusOffline"
        )

        layout.addWidget(
            self.monitor_status_label
        )

        return header


    # ======================================================
    # Sidebar
    # ======================================================

    def _create_sidebar(
        self,
    ) -> QFrame:

        sidebar = QFrame()

        sidebar.setObjectName(
            "sidebarFrame"
        )

        sidebar.setFixedWidth(
            220
        )

        layout = QVBoxLayout(
            sidebar
        )

        layout.setContentsMargins(
            12,
            18,
            12,
            18,
        )

        layout.setSpacing(
            5
        )

        navigation_title = QLabel(
            "NAVIGATION"
        )

        navigation_title.setObjectName(
            "navigationTitle"
        )

        layout.addWidget(
            navigation_title
        )

        # ==================================================
        # Navigation Buttons
        # ==================================================

        navigation_items = [

            (
                "overview",
                "Overview",
            ),

            (
                "incidents",
                "Incidents",
            ),

            (
                "investigation",
                "Investigation",
            ),

            (
                "reports",
                "Reports",
            ),

            (
                "settings",
                "Settings",
            ),
        ]

        for page_key, button_text in navigation_items:

            button = QPushButton(
                button_text
            )

            button.setObjectName(
                "navButton"
            )

            button.setCheckable(
                True
            )

            button.setCursor(
                Qt.PointingHandCursor
            )

            button.clicked.connect(

                lambda checked=False,
                key=page_key:
                    self.show_page(
                        key
                    )
            )

            self.nav_buttons[
                page_key
            ] = button

            layout.addWidget(
                button
            )

        layout.addStretch()

        # ==================================================
        # Version
        # ==================================================

        version_label = QLabel(
            "Intelligent SOC Assistant\nDesktop Edition"
        )

        version_label.setObjectName(
            "navigationTitle"
        )

        version_label.setAlignment(
            Qt.AlignLeft
        )

        layout.addWidget(
            version_label
        )

        return sidebar


    # ======================================================
    # Content Area
    # ======================================================

    def _create_content_area(
        self,
    ) -> QFrame:

        content_frame = QFrame()

        content_frame.setObjectName(
            "contentFrame"
        )

        layout = QVBoxLayout(
            content_frame
        )

        layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        self.page_stack = (
            QStackedWidget()
        )

        # ==================================================
        # Pages
        # ==================================================

        self.pages = {
            
            "overview":
                OverviewPage(
                    database=self.database
                    ),
            "incidents":
                IncidentsPage(
                database=self.database
                    ),

            "investigation":
                InvestigationPage(
                database=self.database
                    ),

            "reports":
    ReportsPage(
        database=self.database
    ),

            "settings":
    SettingsPage(
        project_root=PROJECT_ROOT
    ),
        }

        for page in self.pages.values():

            self.page_stack.addWidget(
                page
            )

        layout.addWidget(
            self.page_stack
        )

        return content_frame


    # ======================================================
    # Bottom Status Bar
    # ======================================================

    def _create_status_bar(
        self,
    ) -> QFrame:

        status_frame = QFrame()

        status_frame.setObjectName(
            "statusFrame"
        )

        status_frame.setFixedHeight(
            38
        )

        layout = QHBoxLayout(
            status_frame
        )

        layout.setContentsMargins(
            16,
            0,
            16,
            0,
        )

        # ==================================================
        # Database Status
        # ==================================================

        if self.database_connected:

            self.database_status_label = QLabel(
                "● Database Connected"
            )

            self.database_status_label.setObjectName(
                "databaseConnected"
            )

        else:

            self.database_status_label = QLabel(
                "● Database Error"
            )

            self.database_status_label.setObjectName(
                "databaseError"
            )

        layout.addWidget(
            self.database_status_label
        )

        layout.addSpacing(
            18
        )

        # ==================================================
        # Database Path
        # ==================================================

        database_path_label = QLabel(

            f"Database: "
            f"{self.database.database_path}"
        )

        database_path_label.setObjectName(
            "statusText"
        )

        layout.addWidget(
            database_path_label
        )

        layout.addStretch()

        # ==================================================
        # Monitor Status
        # ==================================================

        self.bottom_monitor_label = QLabel(
            "Monitoring: Stopped"
        )

        self.bottom_monitor_label.setObjectName(
            "statusText"
        )

        layout.addWidget(
            self.bottom_monitor_label
        )

        return status_frame


    # ======================================================
    # Page Navigation
    # ======================================================

    def show_page(
        self,
        page_key: str,
    ) -> None:

        page = self.pages.get(
            page_key
        )

        if page is None:

            return

        self.page_stack.setCurrentWidget(
            page
        )

        for key, button in (
            self.nav_buttons.items()
        ):

            button.setChecked(
                key == page_key
            )


    # ======================================================
    # Monitoring Status
    # ======================================================

    def set_monitoring_status(
        self,
        running: bool,
    ) -> None:
        """
        Update monitoring status indicators.

        This will be used when background live monitoring
        is integrated later.
        """

        if running:

            self.monitor_status_label.setText(
                "● MONITORING ACTIVE"
            )

            self.monitor_status_label.setObjectName(
                "monitorStatusOnline"
            )

            self.bottom_monitor_label.setText(
                "Monitoring: Active"
            )

        else:

            self.monitor_status_label.setText(
                "● MONITORING STOPPED"
            )

            self.monitor_status_label.setObjectName(
                "monitorStatusOffline"
            )

            self.bottom_monitor_label.setText(
                "Monitoring: Stopped"
            )

        # Reapply style because objectName changed.

        self.monitor_status_label.style().unpolish(
            self.monitor_status_label
        )

        self.monitor_status_label.style().polish(
            self.monitor_status_label
        )
            # ==========================================================
    # Live Monitoring Control
    # ==========================================================

    def start_monitoring(self):
        """
        Start the Windows event monitoring pipeline
        in a background worker.
        """

        if (
            self.monitor_worker is not None
            and self.monitor_worker.isRunning()
        ):
            QMessageBox.information(
                self,
                "Live Monitoring",
                "Live monitoring is already running.",
            )
            return

        self.monitor_worker = MonitorWorker(
            PROJECT_ROOT,
            self,
        )

        self.monitor_worker.status_changed.connect(
            self._handle_monitor_status
        )

        self.monitor_worker.output_received.connect(
            self._handle_monitor_output
        )

        self.monitor_worker.monitor_stopped.connect(
            self._handle_monitor_stopped
        )

        self.start_monitor_button.setEnabled(
            False
        )

        self.stop_monitor_button.setEnabled(
            True
        )

        self.monitor_status_label.setText(
            "● STARTING..."
        )

        self.monitor_worker.start()


    def stop_monitoring(self):
        """
        Stop the background Windows event monitor.
        """

        if self.monitor_worker is None:
            self.set_monitoring_status(False)
            return

        if not self.monitor_worker.isRunning():
            self.set_monitoring_status(False)
            return

        self.stop_monitor_button.setEnabled(
            False
        )

        self.monitor_status_label.setText(
            "● STOPPING..."
        )

        self.monitor_worker.stop_monitoring()


    def _handle_monitor_status(
        self,
        running,
        message,
    ):
        """
        Update desktop controls when monitor state changes.
        """

        self.set_monitoring_status(
            running
        )

        if running:

            self.start_monitor_button.setEnabled(
                False
            )

            self.stop_monitor_button.setEnabled(
                True
            )

        else:

            self.start_monitor_button.setEnabled(
                True
            )

            self.stop_monitor_button.setEnabled(
                False
            )


    def _handle_monitor_output(
        self,
        message,
    ):
        """
        Receive monitor console output without blocking GUI.
        """

        print(
            "[LIVE MONITOR]",
            message,
        )


    def _handle_monitor_stopped(self):
        """
        Restore controls and refresh database-backed pages
        after monitoring stops.
        """

        self.set_monitoring_status(
            False
        )

        self.start_monitor_button.setEnabled(
            True
        )

        self.stop_monitor_button.setEnabled(
            False
        )

        try:

            overview = self.pages.get(
                "overview"
            )

            if (
                overview is not None
                and hasattr(
                    overview,
                    "refresh_dashboard",
                )
            ):
                overview.refresh_dashboard()

        except Exception as error:
            print(
                "[REFRESH WARNING]",
                error,
            )

        try:

            incidents = self.pages.get(
                "incidents"
            )

            if incidents is not None:

                if hasattr(
                    incidents,
                    "refresh_incidents",
                ):
                    incidents.refresh_incidents()

                elif hasattr(
                    incidents,
                    "refresh_data",
                ):
                    incidents.refresh_data()

        except Exception as error:
            print(
                "[REFRESH WARNING]",
                error,
            )

        try:

            reports = self.pages.get(
                "reports"
            )

            if (
                reports is not None
                and hasattr(
                    reports,
                    "refresh_incidents",
                )
            ):
                reports.refresh_incidents()

        except Exception as error:
            print(
                "[REFRESH WARNING]",
                error,
            )


    # ======================================================
    # Apply Styles
    # ======================================================

    def _apply_styles(
        self,
    ) -> None:

        self.setStyleSheet(
            APP_STYLESHEET
        )


# ==========================================================
# Run Desktop Application
# ==========================================================

def run_desktop_application() -> int:
    """
    Start the PySide6 desktop application.
    """

    app = QApplication.instance()

    if app is None:

        app = QApplication(
            sys.argv
        )

    app.setApplicationName(
        "Intelligent SOC Assistant"
    )

    app.setOrganizationName(
        "Intelligent SOC Assistant"
    )

    app.setFont(
        QFont(
            "Segoe UI",
            10,
        )
    )

    window = MainWindow()

    window.show()

    return app.exec()


# ==========================================================
# Direct Run
# ==========================================================

if __name__ == "__main__":

    sys.exit(
        run_desktop_application()
    )