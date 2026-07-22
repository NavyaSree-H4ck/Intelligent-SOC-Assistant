# 🛡️ Intelligent SOC Assistant

A Python-based defensive security application designed to monitor Windows security events, correlate related activity, detect suspicious behavior, prioritize incidents, map relevant detections to MITRE ATT&CK, and support SOC-style investigation through a desktop dashboard.

---

## 📌 Project Overview

The **Intelligent SOC Assistant** is a lightweight security monitoring and incident analysis system developed using Python.

The project monitors security-relevant Windows events and processes them through a modular SOC pipeline:

**Event Collection → Parsing → Normalization → Correlation → Detection → Severity & Risk Scoring → MITRE ATT&CK Mapping → Recommendations → Storage → Investigation & Reporting**

The application provides a native desktop dashboard where security incidents can be monitored, filtered, investigated, and documented.

---

## 💡 Why I Built This Project

My career goal is to become a **SOC Analyst**, and I wanted to understand security monitoring beyond theoretical concepts.

I started with a simple question:

> How can I understand and detect suspicious activity occurring on a Windows system that I control?

Instead of relying only on an existing SIEM interface, I wanted to understand what happens behind a simplified security monitoring pipeline.

This led me to build individual components for:

- Security event collection
- Log parsing
- Normalization
- Event correlation
- Detection
- Incident prioritization
- MITRE ATT&CK enrichment
- Investigation
- Reporting

The idea was to first understand defensive monitoring at the **single-endpoint level** and build a foundation that could later be extended toward larger organizational environments.

---

## 🎯 Objectives

- Monitor Windows security events continuously.
- Extract useful information from raw Windows Event XML.
- Normalize different event structures into a common format.
- Correlate related events before generating meaningful detections.
- Reduce unnecessary alerts and false positives.
- Detect configured security-relevant behavior.
- Assign severity, risk score, and response priority.
- Map supported detections to MITRE ATT&CK.
- Store incidents persistently.
- Provide an analyst-friendly investigation interface.
- Generate structured incident reports.

---

## 🏗️ Architecture

```text
Windows Event Logs
        ↓
Live Event Monitor
        ↓
Parser
        ↓
Normalizer
        ↓
Correlation Engine
        ↓
Detection Engine
        ↓
Severity & Risk Assessment
        ↓
MITRE ATT&CK Mapping
        ↓
Recommendation Engine
        ↓
SQLite Incident Database
        ↓
PySide6 SOC Dashboard
        ↓
Investigation & PDF Reporting