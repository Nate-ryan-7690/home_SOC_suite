// ============================================================
// dashboard.js — Night's Watch SOC Dashboard
// All polling, DOM updates, and action handlers
// ============================================================

const SESSION_START    = new Date();
let   sessionAlertCount = 0;
let   knownAlertIds     = new Set();

// Maps health_db collector_name → dot ID suffix (script filename)
const HEARTBEAT_TO_DOT = {
    "sentinel":        "Sentinel.ps1",
    "bulwark":         "Bulwark.ps1",
    "steward":         "Steward.ps1",
    "cityguard":       "CITYGUARD.ps1",
    "watchman":        "Watchman.ps1",
    "registry_warden": "Registry_Warden.ps1",
    "harbinger":       "Harbinger.ps1",
    "bloodhound":      "Bloodhound.ps1",
    "warden":          "Warden.ps1",
    "seceventlog":     "SecEventLog.ps1",
    "doh_detector":    "DOH_Detector.ps1",
    "sysmonwatcher":   "SysmonWatcher.ps1",
};


// ============================================================
// INIT
// ============================================================
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("session-start").textContent =
        SESSION_START.toLocaleTimeString();

    // Initial load
    refreshStatus();
    refreshSteward();
    refreshSentinel();
    refreshAlerts();
    refreshQuiet();

    // Polling intervals
    setInterval(refreshStatus,   5000);    // 5s — process check
    setInterval(refreshSteward,  5000);    // 5s — status file
    setInterval(refreshSentinel, 5000);    // 5s — SQLite
    setInterval(refreshAlerts,   5000);    // 5s — SQLite
    setInterval(refreshQuiet,    5000);    // 5s — SQLite
});


// ============================================================
// STATUS DOTS
// Three states: green (ACTIVE), amber (UNKNOWN), red (DOWN)
// Heartbeat is ground truth. Process scan is fallback when
// hocsoc_health.db has no entry yet (engine not started).
// Both the status grid dot and the quiet card dot share the
// same id attribute — querySelectorAll updates both at once.
// ============================================================
function refreshStatus() {
    Promise.all([
        fetch("/api/status").then(r => r.json()),
        fetch("/api/heartbeat").then(r => r.json())
    ]).then(([procStatus, heartbeat]) => {
        // Engine dot — PID file only, no heartbeat
        document.querySelectorAll('[id="dot-engine"]')
            .forEach(d => d.className = "dot " + (procStatus["engine"] ? "green" : "red"));

        // Collector dots — heartbeat is ground truth, process scan is fallback
        for (const [hbName, dotName] of Object.entries(HEARTBEAT_TO_DOT)) {
            const hb = heartbeat[hbName];
            let color;
            if (!hb) {
                // No health_db entry yet — engine hasn't run; use process detection
                color = procStatus[dotName] ? "amber" : "red";
            } else if (hb.status === "ACTIVE") {
                color = "green";
            } else if (hb.status === "DOWN") {
                color = "red";
            } else {
                // UNKNOWN — file missing or unreadable
                color = "amber";
            }
            document.querySelectorAll('[id="dot-' + dotName + '"]')
                .forEach(d => d.className = "dot " + color);
        }
    }).catch(() => {});
}


// ============================================================
// STEWARD PANEL — reads Steward_Status.json directly
// ============================================================
function refreshSteward() {
    fetch("/api/steward")
        .then(r => r.json())
        .then(data => {
            if (!data) {
                setEl("steward-system", "<div class='event-line'>Steward not running</div>");
                setEl("steward-disk",   "");
                setEl("steward-cpu",    "");
                setEl("steward-ram",    "");
                return;
            }

            // Section 1 — System health
            const cpuClass = tierClass(data.cpu_total);
            const ramClass = tierClass(data.ram_pct);
            setEl("steward-system", `
                <div class="resource-row">
                    <span class="resource-name">CPU Total</span>
                    <div class="bar-container">
                        <div class="bar-fill ${cpuClass || 'low'}" style="width:${data.cpu_total}%"></div>
                    </div>
                    <span class="resource-val ${cpuClass}">${data.cpu_total}%</span>
                </div>
                <div class="resource-row">
                    <span class="resource-name">RAM Total</span>
                    <div class="bar-container">
                        <div class="bar-fill ${ramClass || 'low'}" style="width:${data.ram_pct}%"></div>
                    </div>
                    <span class="resource-val ${ramClass}">${data.ram_pct}%
                        <span style="color:#555"> (${data.ram_used_gb} / ${data.ram_total_gb} GB)</span>
                    </span>
                </div>`);

            // Section 4 — Disk I/O
            if (data.disk_read_kbs !== null && data.disk_read_kbs !== undefined) {
                const dClass = diskClass(data.disk_read_kbs, data.disk_write_kbs);
                setEl("steward-disk", `
                    <div class="resource-row">
                        <span class="resource-name">Read</span>
                        <span class="resource-val ${dClass}">${data.disk_read_kbs} KB/s</span>
                    </div>
                    <div class="resource-row">
                        <span class="resource-name">Write</span>
                        <span class="resource-val ${dClass}">${data.disk_write_kbs} KB/s</span>
                    </div>`);
            } else {
                setEl("steward-disk", "<div class='event-line'>Unavailable</div>");
            }

            // Section 2 — Top CPU
            if (data.top_cpu && data.top_cpu.length) {
                setEl("steward-cpu", data.top_cpu.map(p => `
                    <div class="resource-row">
                        <span class="resource-name sev-${p.severity}">${p.name}</span>
                        <span class="resource-val">${p.cpu_pct}%
                            <span style="color:#444"> ${p.ram_mb}MB</span>
                        </span>
                    </div>`).join(""));
            } else {
                setEl("steward-cpu", "<div class='event-line'>No data this cycle</div>");
            }

            // Section 3 — Top RAM
            if (data.top_ram && data.top_ram.length) {
                setEl("steward-ram", data.top_ram.map(p => `
                    <div class="resource-row">
                        <span class="resource-name">${p.name}</span>
                        <span class="resource-val">${p.ram_mb} MB</span>
                    </div>`).join(""));
            } else {
                setEl("steward-ram", "<div class='event-line'>No data</div>");
            }

            document.getElementById("steward-updated").textContent =
                data.timestamp || new Date().toLocaleTimeString();
        })
        .catch(() => {
            setEl("steward-system", "<div class='event-line'>Unavailable</div>");
        });
}


// ============================================================
// SENTINEL PANEL
// ============================================================
function refreshSentinel() {
    fetch("/api/sentinel")
        .then(r => r.json())
        .then(rows => {
            if (!rows.length) {
                setEl("sentinel-content", "<div class='event-line'>No connections recorded</div>");
                return;
            }
            setEl("sentinel-content", rows.map(r => `
                <div class="resource-row">
                    <span class="resource-name sev-${r.base_severity || 'OK'}">${r.actor || "—"}</span>
                    <span class="resource-val">${r.destination || "—"}</span>
                    <span style="color:#666; font-size:10px; flex-shrink:0">
                        ${shortTime(r.observed_at)}
                    </span>
                </div>`).join(""));

            document.getElementById("sentinel-updated").textContent =
                new Date().toLocaleTimeString();
        })
        .catch(() => {});
}


// ============================================================
// ALERT FEED
// ============================================================
function refreshAlerts() {
    fetch("/api/alerts")
        .then(r => r.json())
        .then(rows => {
            // Count new alerts created after session start
            rows.forEach(a => {
                if (!knownAlertIds.has(a.alert_id)) {
                    knownAlertIds.add(a.alert_id);
                    if (new Date(a.created_at) >= SESSION_START) {
                        sessionAlertCount++;
                    }
                }
            });
            document.getElementById("alert-count").textContent = sessionAlertCount;
            const newestAlert = rows[0];
            document.getElementById("alerts-updated").textContent =
                "polled " + new Date().toLocaleTimeString() +
                (newestAlert ? " — latest alert " + shortTime(newestAlert.created_at) : "");

            if (!rows.length) {
                setEl("alert-feed", "<div class='event-line' style='padding:8px'>No alerts</div>");
                return;
            }

            setEl("alert-feed", rows.map(a => {
                const sev  = a.severity_current || "UNKNOWN";
                const conf = Math.round((a.confidence || 0) * 100);
                return `
                <div class="alert-row ${sev}">
                    <div class="alert-meta">
                        <span class="alert-sev ${sev}">${sev}</span>
                        <span class="alert-rule">Rule ${a.rule_id}</span>
                        <span class="alert-conf">${conf}%</span>
                        <span class="alert-time">${shortTime(a.created_at)}</span>
                    </div>
                    <div class="alert-explanation">${a.explanation || ""}</div>
                </div>`;
            }).join(""));
        })
        .catch(() => {});
}


// ============================================================
// QUIET COLLECTOR CARDS
// ============================================================
const CARD_MAP = {
    "cityguard":       "cityguard",
    "watchman":        "watchman",
    "registry_warden": "registry_warden",
    "seceventlog":     "seceventlog",
    "doh_detector":    "doh_detector",
    "bloodhound":      "bloodhound",
    "harbinger":       "harbinger",
    "warden":          "warden",
    "sysmonwatcher":   "sysmonwatcher",
};

function refreshQuiet() {
    Promise.all([
        fetch("/api/quiet").then(r => r.json()),
        fetch("/api/quiet/counts").then(r => r.json())
    ]).then(([events, counts]) => {

        // Group events by collector
        const byCollector = {};
        events.forEach(e => {
            if (!byCollector[e.collector_name]) byCollector[e.collector_name] = [];
            byCollector[e.collector_name].push(e);
        });

        for (const [name, id] of Object.entries(CARD_MAP)) {
            const card  = document.getElementById("card-" + id);
            const evEl  = document.getElementById("events-" + id);
            const cntEl = document.getElementById("count-" + id);
            if (!card || !evEl) continue;

            const evs     = byCollector[name] || [];
            const total   = counts[name] || 0;
            const hasCrit = evs.some(e => e.base_severity === "CRITICAL");
            const hasSusp = evs.some(e => e.base_severity === "SUSPICIOUS");

            // Card highlight
            card.className = "quiet-card" +
                (hasCrit ? " critical-highlight" :
                 hasSusp ? " alert-highlight" : "");

            // Counter
            if (cntEl) cntEl.textContent = total ? `${total} events` : "";

            // Event lines — up to 5, most recent first
            if (!evs.length) {
                evEl.innerHTML = "<div class='event-line'>No flags</div>";
            } else {
                evEl.innerHTML = evs.slice(0, 5).map(e => `
                    <div class="event-line sev-${e.base_severity}">
                        [${e.base_severity}] ${e.subtype || ""}
                        ${e.actor ? "— " + e.actor : ""}
                        <span style="color:#666"> ${shortTime(e.observed_at)}</span>
                    </div>`).join("");
            }
        }
    }).catch(() => {});
}


// ============================================================
// ACTION HANDLERS
// ============================================================
async function startDay() {
    const btn = document.getElementById("btn-start-day");
    btn.disabled = true;
    setAuditorMsg("Running Auditor Morning...", "#aaa");

    await fetch("/api/launch/auditor/Morning", { method: "POST" });
    await sleep(10000);
    setAuditorMsg("Auditor complete. Launching suite...", "#8f8");

    const sequence = [
        "Warden.ps1",
        "Sentinel.ps1", "Bulwark.ps1", "Steward.ps1", "CITYGUARD.ps1",
        "Watchman.ps1", "Registry_Warden.ps1", "Harbinger.ps1",
        "Bloodhound.ps1", "SecEventLog.ps1", "DOH_Detector.ps1",
        "SysmonWatcher.ps1"
    ];

    for (const name of sequence) {
        await fetch("/api/launch/collector/" + name, { method: "POST" });
        await sleep(500);
    }

    await sleep(2000);
    await fetch("/api/launch/engine", { method: "POST" });

    setAuditorMsg("Suite started. Engine running.", "#8f8");
    btn.disabled = false;
    refreshStatus();
}


async function endDay() {
    const btn = document.getElementById("btn-end-day");
    btn.disabled = true;
    setAuditorMsg("Stopping collectors...", "#aaa");

    await fetch("/api/stop/all", { method: "POST" });
    setAuditorMsg("Collectors stopped. Engine terminated.", "#fa4");
    await sleep(3000);

    setAuditorMsg("Running Auditor Evening...", "#aaa");
    await fetch("/api/launch/auditor/Evening", { method: "POST" });
    await sleep(10000);

    setAuditorMsg("Evening audit complete. Safe to shut down.", "#8f8");
    btn.disabled = false;
    refreshStatus();
    document.getElementById("btn-shutdown").style.display = "";
}


async function shutdownDashboard() {
    const btn = document.getElementById("btn-shutdown");
    btn.disabled = true;
    btn.textContent = "Shutting down...";
    await fetch("/api/shutdown", { method: "POST" }).catch(() => {});
}


async function runWeekly() {
    const btn = document.getElementById("btn-weekly");
    btn.disabled = true;
    setAuditorMsg("Running weekly reports...", "#aaa");

    const r    = await fetch("/api/launch/weekly", { method: "POST" });
    const data = await r.json();

    document.getElementById("weekly-status").textContent =
        `Weekly reports run at ${data.timestamp} — ${data.launched.join(", ")}`;
    setAuditorMsg("Weekly reports complete.", "#8f8");
    btn.disabled = false;
}


// ============================================================
// HELPERS
// ============================================================
function setEl(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function setAuditorMsg(msg, color) {
    const el = document.getElementById("auditor-output");
    if (el) { el.textContent = msg; el.style.color = color; }
}

// Threshold-based CSS class for numeric values
function sevClass(val, crit, susp, warn) {
    if (val >= crit) return "crit";
    if (val >= susp) return "warn";
    if (warn !== undefined && val >= warn) return "warn";
    return "ok";
}

// 4-tier load scale for bar graphs — independent of event severity classification
// <50 low / 50-75 mid / 75-90 high / 90+ max
function tierClass(val) {
    if (val >= 90) return "max";
    if (val >= 75) return "high";
    if (val >= 50) return "mid";
    return "low";
}

function diskClass(read, write) {
    if (read > 50000 || write > 50000) return "crit";
    if (read > 10000 || write > 10000) return "warn";
    return "";
}

function shortTime(ts) {
    if (!ts) return "—";
    try { return new Date(ts).toLocaleTimeString(); }
    catch { return ts; }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Expand/collapse event lines on click (works on dynamically rendered content)
document.addEventListener('click', e => {
    const line = e.target.closest('.event-line');
    if (line) line.classList.toggle('expanded');
});
