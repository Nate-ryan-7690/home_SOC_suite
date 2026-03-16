# Home SOC Suite — Night's Watch

A personal Security Operations Center (SOC) built from scratch during an 
Anwendungsentwicklung retraining program. This suite monitors a Windows endpoint 
for network anomalies, resource spikes, scheduled task changes, and power events 
— logging everything to structured files for weekly analysis and future 
integration into a Python dashboard.

---

## Background

Built as a practical learning project alongside formal IT retraining, this suite 
applies real SOC concepts — baseline collection, anomaly detection, severity 
classification, and log aggregation — to a personal Windows machine. The goal is 
to understand the full monitoring pipeline from data collection through to 
analysis, preparing for a career in cyber defense.

---

## Architecture

The suite follows a two layer architecture:

**Collection Layer** — PowerShell scripts that run continuously in the background, 
each monitoring a specific data source and writing structured, severity-tagged log 
entries.

**Analysis Layer** — PowerShell analyst scripts that parse the collected logs and 
generate weekly summary reports.

A Python dashboard combining all data sources is planned as the next phase.

---

## Scripts

### Collectors

| Script | Shortcut | Function |
|--------|----------|----------|
| Sentinel.ps1 | Network Watchdog | Monitors outbound TCP connections with geolocation and process path verification |
| Bulwark.ps1 | Night's Watch | Monitors inbound listening ports for changes and geolocation anomalies |
| Steward.ps1 | Quartermaster | Monitors CPU, RAM and disk I/O per process using Windows performance counters |
| CityGuard.ps1 | City Guard | Monitors scheduled tasks for additions, deletions and modifications |
| Watchman.ps1 | Watchman | Monitors Windows power events — boot, sleep, wake and unexpected shutdowns |

### Analysts

| Script | Shortcut | Function |
|--------|----------|----------|
| Investigator.ps1 | Audit Reporter | Weekly analysis of Sentinel outbound connection logs |
| Crow.ps1 | Lord Commander | Weekly analysis of Bulwark inbound port logs |
| Ledger.ps1 | Maester | Weekly analysis of Steward resource logs with RAM trend detection |
| Castellan.ps1 | Castellan | Weekly analysis of CityGuard scheduled task logs |

---

## Severity System

All collectors use a consistent four level severity system:

| Level | Color | Meaning |
|-------|-------|---------|
| OK | Green | Matches known baseline, no action needed |
| UNKNOWN | Yellow | Not yet baselined, monitor for patterns |
| SUSPICIOUS | DarkYellow | Anomaly detected, investigate |
| CRITICAL | Red | Threshold breached, immediate review |

---

## Log Structure

All logs follow a consistent format for future Python parsing:
```
[yyyy-MM-dd HH:mm:ss] [SEVERITY] Event details
```

Logs are stored in a structured folder hierarchy:
```
Desktop/SOC/
├── Scripts/        — PowerShell collector and analyst scripts
├── Logs/           — Active log files
│   └── Archives/   — 7 day archived logs
├── Reports/        — Weekly analyst reports
└── Config/         — Baseline files (JSON)
```

---

## Key Features

- **Behavioral baseline collection** — all collectors build baselines over time, 
  enabling anomaly detection based on observed normal behavior rather than static rules
- **Geolocation monitoring** — outbound and inbound connections tracked by country, 
  enabling detection of unexpected geographic destinations
- **Process fingerprinting** — every connection and port event logged with full 
  process path, detecting masquerading attacks
- **Severity tagged logging** — structured log entries enable automated parsing 
  and future SIEM integration
- **7 day log rotation** — automatic archiving keeps logs manageable while 
  preserving history
- **German Windows compatibility** — performance counter paths localized for 
  German Windows installations

---

## Planned Next Phase

- Python dashboard using Flask and Chart.js
- Live visualization of all five data streams
- Whitelist integration after one month baseline period
- DNS query monitoring
- File integrity monitoring

---

## Notes

- Scripts require PowerShell execution policy set to Bypass
- Collector scripts require Administrator elevation for full system visibility
- Analyst scripts run as standard user
- Performance counter paths use German localization — adjust for other Windows 
  language installations
- Geolocation provided by ip-api.com free tier

---

## Learning Context

Built during Fachinformatiker Anwendungsentwicklung retraining, Germany 2026.  
Targeting a career in cyber defense and threat intelligence. 
Built with AI assistance as a learning tool. Every design decision, 
debugging session and architectural choice was driven by the developer 
with full understanding of the underlying concepts.
