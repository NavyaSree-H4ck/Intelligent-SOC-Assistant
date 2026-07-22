# 🛡️ Intelligent SOC Assistant

A Python-based defensive security application that monitors Windows security events, detects suspicious activity, correlates related events, assigns severity and risk, maps detections to MITRE ATT&CK, and supports SOC-style incident investigation through a desktop dashboard.

---

## 📌 Project Overview

The **Intelligent SOC Assistant** was developed to understand how a Security Operations Center (SOC) processes security events from collection to investigation.

The project follows this pipeline:

**Event Collection → Parsing → Normalization → Correlation → Detection → Severity & Risk Scoring → MITRE ATT&CK Mapping → Recommendations → Storage → Investigation & Reporting**

The application monitors Windows security events and converts raw event data into structured security incidents that can be analyzed through a desktop GUI.

---

## 💡 Why I Built This Project

My career goal is to become a **SOC Analyst**, and I wanted to move beyond theoretical cybersecurity concepts and understand how security monitoring works practically.

I started with the idea of learning how to **monitor and defend a Windows system that I control** before extending that knowledge toward larger organizational environments.

Instead of only using an existing SIEM tool, I wanted to understand the components behind a security monitoring pipeline—how logs are collected, parsed, correlated, detected, prioritized, investigated, and reported.

---

## 🏗️ Architecture

```text
Windows Security & PowerShell Events
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
      Severity & Risk Scoring
                ↓
       MITRE ATT&CK Mapper
                ↓
      Recommendation Engine
                ↓
       SQLite Incident Database
                ↓
       PySide6 SOC Dashboard
                ↓
      Investigation & Reporting
```

---

## ⚙️ How It Works

### 1. Event Collection
The live monitor collects configured security-relevant events from **Windows Security** and **PowerShell Operational** logs.

### 2. Parsing
Raw Windows Event XML is processed to extract useful fields such as Event ID, timestamp, username, hostname, source IP, logon type, process information, and record ID.

### 3. Normalization
Different event structures are converted into a consistent internal format so all modules can process them uniformly.

### 4. Correlation
Related events are connected using factors such as time window, username, host, source, event type, and thresholds.

For example:

```text
Failed Login #1
        ↓
Failed Login #2
        ↓
Failed Login #3
        ↓
Correlation Threshold Reached
        ↓
One Meaningful Detection
```

This helps reduce unnecessary alert flooding.

### 5. Detection & Prioritization
The detection engine identifies configured suspicious behavior and assigns:

- Severity
- Risk score
- Response priority

### 6. MITRE ATT&CK & Recommendations
Supported detections are mapped to relevant MITRE ATT&CK techniques and enriched with investigation or response recommendations.

### 7. Storage & Investigation
Incidents are stored using SQLite and displayed through the PySide6 dashboard for analysis, filtering, investigation, and PDF reporting.

---

## 🔍 Detection Scenarios

The project was tested using controlled activities in an authorized environment.

| Detection Scenario | Event ID | MITRE ATT&CK |
|---|---:|---|
| Repeated authentication failures / potential brute force | 4625 | T1110 |
| Suspicious PowerShell activity | 4104 | T1059.001 |
| User account creation | 4720 | T1136.001 |
| User account deletion | 4726 | Context dependent |
| Security group membership modification | 4728 / 4732 | T1098 |
| Security audit log cleared | 1102 | T1070.001 |

> **An Event ID alone does not prove an attack. Detection requires context, correlation, evidence, and analyst investigation.**

More details are available in `docs/DETECTION_SCENARIOS.md`.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| **Python** | Core security-processing and application logic |
| **pywin32** | Windows Event Log access |
| **XML** | Processing structured Windows event data |
| **PySide6 / Qt** | Desktop graphical user interface |
| **SQLite** | Local incident storage |
| **Matplotlib** | Dashboard charts and visualizations |
| **MITRE ATT&CK** | Mapping detected behavior to adversary techniques |
| **ReportLab** | PDF incident report generation |
| **PyInstaller** | Packaging the application |
| **venv** | Isolated Python environment |

---

## 📊 Dashboard Preview

### Security Overview

Displays security KPIs, incident statistics, severity information, and visualizations.

![Security Overview](screenshots/security_overview.png)

### Incident Management

Allows analysts to search, filter, review, and prioritize detected incidents.

![Incident Management](screenshots/incident_management.png)

### Incident Investigation

Provides detection details, evidence, severity, risk score, MITRE ATT&CK mapping, and recommendations.

![Incident Investigation](screenshots/incident_investigation.png)

### Report Center

Supports structured PDF incident report generation.

![Report Center](screenshots/report_center.png)

---

## 📁 Project Structure

```text
Intelligent-SOC-Assistant/
│
├── dashboard/          # PySide6 desktop interface
├── database/           # SQLite database operations
├── detection/          # Detection and correlation engines
├── docs/               # Detection documentation
├── live_monitor/       # Windows event monitoring
├── mitre/              # MITRE ATT&CK mapping
├── normalizer/         # Event normalization
├── parser/             # Windows XML parsing
├── recommendation/     # Investigation recommendations
├── reports/            # PDF report generation
├── screenshots/        # Dashboard screenshots
├── severity/           # Severity and risk assessment
│
├── main.py             # Application entry point
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Installation & Usage

### 1. Clone the repository

```bash
git clone <https://github.com/NavyaSree-H4ck/Intelligent-SOC-Assistant.git>
cd Intelligent-SOC-Assistant
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
```

PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python main.py
```

Appropriate Windows permissions and auditing configuration may be required to access some security event channels.

---

## 🚧 Challenges & Learning

Some of the main challenges during development were:

- Understanding complex Windows Event XML structures.
- Extracting correct fields across different Event IDs.
- Normalizing inconsistent event data.
- Designing correlation thresholds and time windows.
- Reducing false positives and alert flooding.
- Differentiating local and remote authentication context.
- Mapping detections appropriately to MITRE ATT&CK.
- Integrating monitoring, detection, database, GUI, and reporting modules.
- Keeping the desktop interface responsive during live monitoring.

Working through these challenges gave me practical exposure to **Windows security logs, detection engineering, event correlation, SOC alert triage, MITRE ATT&CK, incident investigation, Python application development, and defensive security workflows**.

---

## 🔮 Future Scope

The current implementation primarily focuses on a Windows endpoint. Future improvements could include:

- Multi-endpoint centralized monitoring
- Sysmon and Linux log integration
- Firewall, IDS/IPS, and EDR telemetry
- Threat intelligence and IOC enrichment
- Additional behavioral detection rules
- Machine-learning-assisted anomaly detection
- Centralized scalable storage
- Alert notifications and case management
- SOAR-style automated response workflows

---

## 🎯 Connection to My Career Goal

As an aspiring **SOC Analyst**, this project helped me understand the defensive workflow behind security monitoring:

**Monitor → Detect → Correlate → Prioritize → Investigate → Respond → Report**

I approached the project with the idea of first understanding how to monitor and secure an endpoint I control, then building those skills toward protecting larger organizational environments.

---

## ⚠️ Disclaimer

This project is intended only for **educational, defensive-security, and authorized testing purposes**.

Security testing should only be performed on systems you own or have explicit permission to test.

This is a learning-oriented SOC prototype and is not intended to replace enterprise SIEM or EDR platforms.

---

## 👩‍💻 Author

**Navya Sree K**  
Cybersecurity Student | Aspiring SOC Analyst

**Interests:** SOC Operations • Blue Team • Threat Detection • Incident Investigation • Detection Engineering • Defensive Cybersecurity

---

> **Monitor. Detect. Correlate. Investigate. Respond. Defend. 🛡️**

⭐ If you find this project useful, consider starring the repository.