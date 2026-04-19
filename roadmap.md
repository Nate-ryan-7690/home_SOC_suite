# 🛡️ Night's Watch SOC Suite: Strategic Development Roadmap

> **Note:** This roadmap reflects the current direction of the project and may evolve based on operational testing, learning progress, and available development time.

---

## 📍 Phase 8: Intelligence-Driven Correlation *(Current)*  
**Status:** Active  
**Target Window:** April 2026

Current focus is enhancing the Correlation Engine from static rule execution to a more adaptive, intelligence-informed model.

### Objectives
- Integrate approved indicators from the **Intel Pipeline** into correlation logic
- Apply confidence-weighted intelligence to enrich detections and prioritization
- Complete the initial 30-day baseline period to establish normal system behavior
- Refine alert thresholds, rule tuning, and dashboard stability
- Continue hardening the Flask dashboard for reliable daily use

---

## 🔍 Phase 9: Forensic Engine & Deep Analytics  
**Status:** Planned  
**Target Window:** Q3 2026

Expand the suite from detection into structured incident investigation and post-event analysis.

### Objectives
- Build a dedicated **Forensic Engine** for:
  - timeline reconstruction
  - process lineage tracing
  - beaconing pattern analysis
  - persistence review
- Create a unified dashboard for evidence chains and investigative workflows
- Generate standardized forensic reports for review and documentation
- Maintain append-only evidence handling where practical

---

## 🐧 Phase 10: Linux Expansion (Debian Focus)  
**Status:** Planned  
**Priority:** High

Extend monitoring and analytics capabilities into Linux environments.

### Objectives
- Develop native Linux telemetry collectors
- Evaluate tools such as `auditd`, `journald`, and `eBPF`
- Build normalized schemas compatible with existing backend logic
- Support cross-platform correlation between Windows and Linux sources
- Research collector hardening and tamper-resistance controls

---

## 🏗️ Phase 11: Adversarial Simulation Lab & Multi-Endpoint Monitoring  
**Status:** Long-Term  
**Estimated Window:** 2027–2028

Evolve from single-endpoint monitoring into a small distributed security lab environment.

### Objectives
- Deploy a multi-node virtualized lab for realistic testing
- Run controlled adversarial simulations to validate detections
- Expand architecture to support multiple monitored endpoints
- Centralize alerting and correlation across hosts
- Improve analyst workflows for multi-system investigations

---

## ⏳ Long-Term Vision

Night's Watch is intended to grow into an open-source personal SOC toolkit focused on:

- high-fidelity behavioral detection
- intelligence-assisted prioritization
- practical forensic workflows
- Windows and Linux endpoint visibility
- local-first operation without commercial dependencies

---

## 📌 Guiding Principles

- Detection logic should remain explainable and tunable
- Human review is preferred over blind automation
- Features should be driven by practical use cases
- Stability and signal quality take priority over rapid expansion
- The suite should remain useful as a personal defensive platform first
