# Detection Scenarios

This document describes controlled security-event scenarios used to validate the Intelligent SOC Assistant.

All tests were performed in an authorized environment for defensive-security learning.

## 1. Repeated Authentication Failures

**Relevant Event ID:** 4625

### Purpose

Validate whether multiple failed authentication events can be correlated before generating a security incident.

### Expected Flow

```text
Failed Authentication Events
        ↓
Parser
        ↓
Normalizer
        ↓
Correlation Engine
        ↓
Threshold / Time Window Evaluation
        ↓
Detection
        ↓
Incident