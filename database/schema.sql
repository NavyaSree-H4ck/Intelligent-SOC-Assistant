PRAGMA foreign_keys = ON;

-- =========================================================
-- INCIDENTS TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS incidents (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL UNIQUE,

    created_at TEXT NOT NULL,

    detection_type TEXT NOT NULL,

    detection_category TEXT,

    description TEXT,

    confidence TEXT,

    event_id INTEGER,

    event_count INTEGER,

    threshold_value INTEGER,

    first_seen TEXT,

    last_seen TEXT,

    source_ip TEXT,

    source_port INTEGER,

    destination_ip TEXT,

    destination_port INTEGER,

    authentication_scope TEXT,

    username TEXT,

    domain TEXT,

    hostname TEXT,

    host_ip TEXT,

    logon_type INTEGER,

    logon_type_name TEXT,

    process_name TEXT,

    parent_process_name TEXT,

    command_line TEXT,

    base_risk_score INTEGER,

    risk_score INTEGER,

    severity TEXT,

    response_priority TEXT,

    mitre_mapped INTEGER NOT NULL DEFAULT 0,

    mitre_tactic TEXT,

    mitre_technique_id TEXT,

    mitre_technique_name TEXT,

    status TEXT NOT NULL DEFAULT 'OPEN',

    analyst_notes TEXT,

    raw_detection_json TEXT NOT NULL
);


-- =========================================================
-- INCIDENT EVIDENCE
-- =========================================================

CREATE TABLE IF NOT EXISTS incident_evidence (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL,

    evidence_order INTEGER NOT NULL DEFAULT 0,

    evidence_text TEXT NOT NULL,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
);


-- =========================================================
-- RECORD IDs
-- =========================================================

CREATE TABLE IF NOT EXISTS incident_record_ids (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL,

    record_id TEXT NOT NULL,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
);


-- =========================================================
-- MITRE MAPPINGS
-- =========================================================

CREATE TABLE IF NOT EXISTS incident_mitre_mappings (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL,

    tactic TEXT,

    technique_id TEXT,

    technique_name TEXT,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
);


-- =========================================================
-- SEVERITY REASONS
-- =========================================================

CREATE TABLE IF NOT EXISTS incident_severity_reasons (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL,

    reason_order INTEGER NOT NULL DEFAULT 0,

    reason_text TEXT NOT NULL,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
);


-- =========================================================
-- RECOMMENDATIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS incident_recommendations (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id TEXT NOT NULL,

    recommendation_type TEXT NOT NULL,

    recommendation_order INTEGER NOT NULL DEFAULT 0,

    recommendation_text TEXT NOT NULL,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
);


-- =========================================================
-- INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_incidents_created_at
ON incidents(created_at);


CREATE INDEX IF NOT EXISTS idx_incidents_severity
ON incidents(severity);


CREATE INDEX IF NOT EXISTS idx_incidents_detection_type
ON incidents(detection_type);


CREATE INDEX IF NOT EXISTS idx_incidents_status
ON incidents(status);


CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
ON incidents(source_ip);


CREATE INDEX IF NOT EXISTS idx_incidents_mitre_technique
ON incidents(mitre_technique_id);


CREATE INDEX IF NOT EXISTS idx_evidence_incident
ON incident_evidence(incident_id);


CREATE INDEX IF NOT EXISTS idx_record_ids_incident
ON incident_record_ids(incident_id);


CREATE INDEX IF NOT EXISTS idx_mitre_incident
ON incident_mitre_mappings(incident_id);


CREATE INDEX IF NOT EXISTS idx_severity_reasons_incident
ON incident_severity_reasons(incident_id);


CREATE INDEX IF NOT EXISTS idx_recommendations_incident
ON incident_recommendations(incident_id);