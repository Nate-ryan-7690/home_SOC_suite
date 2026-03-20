# Home SOC Suite — Night's Watch

A personal Security Operations Center (SOC) built from scratch during an
Anwendungsentwicklung retraining program. This suite monitors a Windows endpoint
for network anomalies, resource spikes, process execution, registry changes,
Security Event Log activity, scheduled task changes, DNS queries, and power events
— logging everything to structured files for weekly analysis and correlation
through a Python engine.

---

## Background

Built as a practical learning project alongside formal IT retraining, this suite
applies real SOC concepts — baseline collection, anomaly detection, severity
classification, log aggregation, and cross-source correlation — to a personal
Windows machine. The design process was adversarial from the start: each phase
was stress-tested against a red team analysis before the next was built, with
26 correlation rules defined from those findings driving the architecture of the
Python engine.

---

## Architecture

The suite follows a three-layer architecture:

**Collection Layer** — PowerShell collectors that run continuously in the
background, each monitoring a specific data source and writing structured,
severity-tagged log entries. All require Administrator elevation.

**Analysis Layer** — PowerShell analyst scripts that parse collected logs and
generate weekly summary reports. Run as standard user.

**Correlation Engine (Phase 7 — in progress)** — Python engine that ingests all
collector logs, normalises events to a common schema, and runs 26 rule-based and
risk-scored correlation rules across all data streams. Three programs:

| Program | Role |
|---|---|
| The Brain | Ingest, normalise, correlate, alert (SQLite operational store) |
| The Dashboard | Live visibility — collector health, alerts, evidence chains (Flask + Chart.js) |
| The Steward | Forensic archiving — integrity manifests, archive chain hashes, timeline reconstruction |

---

## Scripts

### Collectors

| Phase | Script | Nickname | Function |
|---|---|---|---|
| 1 | Sentinel.ps1 | Network Watchdog | Outbound TCP connections with geolocation, process path verification, and cumulative transfer tracking |
| 1 | Bulwark.ps1 | Night's Watch | Inbound listening ports — baseline diff, new/closed port detection, geolocation anomalies |
| 1 | Steward.ps1 | Quartermaster | CPU, RAM, and disk I/O per process using Windows performance counters with 8-language auto-detection |
| 1 | CityGuard.ps1 | City Guard | Scheduled task additions, deletions, and modifications — action and trigger change detection |
| 1 | Watchman.ps1 | Watchman | Power events — boot, sleep, wake, unexpected shutdown, and after-hours activity |
| 2A | Registry_Warden.ps1 | — | Registry run keys, RunOnce, Services baseline and diff, SAM RID integrity check |
| 2B | Harbinger.ps1 | — | WMI/CIM event-driven process creation monitor — high-risk path detection, parent process tracking |
| 3 | Bloodhound.ps1 | — | DNS query monitor — DGA detection via Shannon entropy, TXT record flagging, ICMP volume spike detection |
| 4 | Warden.ps1 | — | Suite watchdog — SHA256 script FIM, log size regression, collector health, maintenance flag, self-watch scheduled task |
| 5 | SecEventLog.ps1 | — | Windows Security Event Log — logon anomalies, account manipulation, privilege escalation, service installation, brute force detection |
| 6 | DoH_Detector.ps1 | — | DNS-over-HTTPS evasion detector — TCP connections to 28 known DoH resolver IPs from non-whitelisted processes |

### Analysts

| Script | Nickname | Function |
|---|---|---|
| Investigator.ps1 | Audit Reporter | Weekly analysis of Sentinel outbound connection logs |
| Crow.ps1 | Lord Commander | Weekly analysis of Bulwark inbound port logs |
| Ledger.ps1 | Maester | Weekly analysis of Steward resource logs with RAM trend detection |
| Castellan.ps1 | Castellan | Weekly analysis of CityGuard scheduled task logs |
| Auditor.ps1 | — | Morning/evening bookend integrity audit — SHA256 log verification, archive hash chain validation |

---

## The 26 Correlation Rules

Defined through multi-round red team analysis (see Documentation). Implemented in Phase 7.

| # | Rule | Severity | Sources |
|---|---|---|---|
| 1 | Data Exfiltration Suspected | HIGH | Steward + Sentinel |
| 2 | C2 Beacon Suspected | HIGH | Sentinel + Bulwark |
| 3 | Persistence + C2 Callback | CRITICAL | CityGuard + Sentinel |
| 4 | After Hours Intrusion | CRITICAL | Watchman + Sentinel |
| 5 | Data Staging | HIGH | Bulwark + Steward |
| 6 | LOLBin Network Activity | CRITICAL | Sentinel |
| 7 | Process Hollowing Suspected | CRITICAL | Harbinger + Sentinel |
| 8 | DoH Evasion Suspected | CRITICAL | DoH_Detector |
| 9 | WMI Persistence Suspected | HIGH | Harbinger + CityGuard |
| 10 | Account Manipulation | CRITICAL | SecEventLog |
| 11 | Burst Exfiltration Pattern | HIGH | Sentinel |
| 12 | Sub-Threshold Persistent Process | SUSPICIOUS | Sentinel + Steward |
| 13 | Initial Access Suspected | CRITICAL | Harbinger + Sentinel |
| 14 | Trusted Binary Anomaly | SUSP→CRIT | Sentinel |
| 15 | Statistical Jitter Detector | HIGH | Sentinel |
| 16 | Contextual Integrity Violation | CRITICAL | Harbinger + Sentinel |
| 17 | Identity / RID Hijack | CRITICAL | Registry_Warden + SecEventLog |
| 18 | Correlation Engine Health | MEDIUM | Python Core |
| 19 | Self-Protection / Script FIM | CRITICAL | Warden |
| 20 | Statistical Temporal Drift | MEDIUM | Steward + Sentinel |
| 21 | Interpreter Lockdown / BYOI | HIGH | Harbinger |
| 22 | Cloud API Anomaly | HIGH | Sentinel |
| 23 | HID Injection Detector | CRITICAL | WMI Device Events |
| 24 | Evil Twin / WiFi Ghost | CRITICAL | Network Monitor |
| 25 | Focus Thief / Window Hijack | HIGH | Win32 API |
| 26 | Visit Integrity Check | HIGH | All collectors |

---

## Severity System

All collectors use a consistent four-level severity system:

| Level | Color | Meaning |
|---|---|---|
| OK | Green | Matches known baseline, no action needed |
| UNKNOWN | Yellow | Not yet baselined, monitor for patterns |
| SUSPICIOUS | DarkYellow | Anomaly detected, investigate |
| CRITICAL | Red | Threshold breached, immediate review |

---

## Log Structure

All logs follow a consistent format for Python parser compatibility:
```
[yyyy-MM-dd HH:mm:ss] [SEVERITY] Event details
```

Logs are stored in a structured folder hierarchy:
```
$RootPath/              — default: Desktop\SOC
├── Scripts/            — PowerShell collector and analyst scripts
├── Logs/               — Active log files
│   └── Archives/       — 7-day archived logs
├── Reports/            — Weekly analyst reports
├── Config/             — Baseline and manifest files (JSON)
└── Documentation/      — Research documents and red team analysis
```

---

## Supported OS Languages

Steward automatically detects the correct CPU performance counter path for the
following OS languages:

| Language | Counter Path |
|---|---|
| English | \Process(*)\% Processor Time |
| German | \Prozess(*)\Prozessorzeit (%) |
| French | \Processus(*)\% temps processeur |
| Spanish | \Proceso(*)\% de tiempo de procesador |
| Italian | \Processo(*)\% Tempo processore |
| Portuguese | \Processo(*)\% de Tempo do Processador |
| Russian | \Процесс(*)\% загруженности процессора |
| Chinese (Simp.) | \Process(*)\% Processor Time (typically English) |

To add support for another language, add the localized counter path to the
`$PathsToTry` array in the `Get-WorkingCounterPath` function in `Steward.ps1`.

---

## Documentation & Research

The `Documentation/` folder contains the full research and planning record that
drove the design of this suite. The suite was built adversarially — each layer
was planned against a threat model before it was built, and stress-tested against
a red team analysis before the next layer was started.

| Document | Purpose |
|---|---|
| `home_soc_pre_coding_architecture_guide.pdf` | Pre-build decision framework. Canonical data model, trust model, baseline lifecycle, testing strategy, and cross-collector validation opportunities. Written before a single line of code. |
| `Home_Soc_Architecture_And_Engine_Design.pdf` | Target architecture specification. Three-program Python engine design, SQLite schema, hybrid detection model (deterministic rules + risk scoring), alert promotion logic. |
| `HomSOC_Implementation_Guide.pdf` | Phase-by-phase build plan. Skeleton code for all collectors, weekly work schedule, PowerShell quick reference patterns. The construction manual for the PowerShell layer. |
| `RedTeam_Analysis_HomSOC_Final.pdf` | Primary red team reference. 11 adversarial rounds (Claude + Gemini + live engagement simulations), all 26 correlation rules with full detection logic, bypass findings, and mitigations applied to the build. |
| `Home_SOC_Red_Team_Analysis_Pro.pdf` | Architectural red team. 11 attack scenarios targeting structural weaknesses: baseline poisoning, correlation bypass, noise flooding, collector suppression, archive tampering, log injection, replay attacks, and identity abuse. |
| `Home_SOC_Red_Team_Whitepaper.pdf` | Executive summary. Full attack scenario table, system comparison (baseline vs hardened), key architectural improvements, and detection model design overview. |

---

## Key Features

- **Adversarial design** — 26 correlation rules defined through multi-round red
  team analysis before the Python engine was built. Detection logic is grounded
  in real attack chains, not hypothetical scenarios
- **Behavioral baseline collection** — all collectors build baselines over time,
  enabling anomaly detection relative to observed normal rather than static rules
- **Geolocation monitoring** — outbound connections, inbound connections,
  authentication source IPs, and DoH connections tracked by country with
  TELEMETRY_GAP alerting on geo failures
- **Process fingerprinting** — every network, port, process, and authentication
  event logged with full process path, detecting masquerading and LOLBin attacks
- **Suite self-protection** — Warden monitors all scripts and configurations via
  SHA256 FIM with a three-layer protection chain: manifest integrity, external
  scheduled task, and CityGuard task monitoring
- **Zero-Trust whitelisting** — all whitelists start empty. 30-day baseline
  collection precedes any exception grants
- **Severity-tagged logging** — structured log entries designed for Python parser
  compatibility and future SIEM integration
- **7-day log rotation** — automatic archiving with SHA256 verification and
  archive hash chain integrity checks at morning/evening bookends via Auditor.ps1
- **Multi-language Windows compatibility** — performance counter paths
  auto-detected across 8 OS languages at startup

---

## Planned Next Phase — Python Correlation Engine

The PowerShell collection layer is complete. Phase 7 builds the Python engine.

**Implementation order:**

1. `log_parser.py` — reads all collector logs into structured events
2. `normalizer.py` — maps raw events to canonical normalised schema
3. `correlator.py` — applies 26 rules, starting with Rules 6, 13, and 3
4. `alert_manager.py` — deduplication, throttling, alert log
5. `engine.py` — main loop, orchestration, 5–10 minute polling cycle
6. `config.py` — all thresholds and time windows in one place (rotated
   periodically — static thresholds are attackable)

**Detection model:** Hybrid — deterministic rules for clear attack chains,
risk scoring for cumulative weak signals, visibility alerts for collector
silence and ingest quality degradation.

---

## Notes

- Set `$RootPath` in each script to the folder where you installed the SOC Suite.
  Default is `Desktop\SOC`
- Scripts require PowerShell execution policy set to Bypass
- Collector scripts require Administrator elevation for full system visibility
- Analyst scripts run as standard user
- Geolocation provided by ip-api.com free tier
- DNS Client event log must be enabled before running Bloodhound.ps1:
  `wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true`

---

## Learning Context

Built during Fachinformatiker Anwendungsentwicklung retraining, Germany 2026.
Targeting a career in cyber defense and threat intelligence.
Built with AI assistance as a learning tool. Every design decision,
debugging session and architectural choice was driven by the developer
with full understanding of the underlying concepts.
