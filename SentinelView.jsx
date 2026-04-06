import { useState, useEffect, useRef } from "react";

// ─── DATA ───────────────────────────────────────────────────────────────────

const DETECTION_RULES = [
  {
    id: "SR-001",
    name: "Brute Force Login Attempt",
    severity: "HIGH",
    tactic: "Credential Access",
    technique: "T1110",
    techniqueURL: "https://attack.mitre.org/techniques/T1110/",
    description: "Detects repeated failed authentication attempts against a single account within a short time window, indicative of automated credential stuffing or brute force attacks.",
    logic: 'event.type == "auth_failure" AND count(event.user) >= 5 WITHIN 2m',
    falsePositives: ["Legitimate users who forgot their password", "Automated testing pipelines"],
    response: ["Lock account after threshold breach", "Alert Tier 1 SOC analyst", "Check IP reputation via threat intel", "Review upstream firewall logs"],
    category: "Authentication",
  },
  {
    id: "SR-002",
    name: "Port Scan Detected",
    severity: "MEDIUM",
    tactic: "Reconnaissance",
    technique: "T1046",
    techniqueURL: "https://attack.mitre.org/techniques/T1046/",
    description: "Identifies sequential or distributed TCP SYN packets to multiple ports from a single source IP within a 60-second window, consistent with automated network scanning tools.",
    logic: 'event.type == "network" AND tcp.flags.syn == 1 AND count(dest.port) > 15 WITHIN 60s',
    falsePositives: ["Authorized vulnerability scanners (Nessus, Qualys)", "Internal IT asset discovery tools"],
    response: ["Block source IP at perimeter firewall", "Determine if source is internal or external", "Correlate with asset inventory", "Escalate if targeting critical systems"],
    category: "Network",
  },
  {
    id: "SR-003",
    name: "Privilege Escalation via Sudo",
    severity: "HIGH",
    tactic: "Privilege Escalation",
    technique: "T1548.003",
    techniqueURL: "https://attack.mitre.org/techniques/T1548/003/",
    description: "Detects unexpected sudo execution by non-administrative accounts, particularly commands that spawn shells or modify system binaries.",
    logic: 'event.type == "process" AND process.name == "sudo" AND user.role != "admin" AND process.args CONTAINS ("bash","sh","python")',
    falsePositives: ["DevOps scripts with elevated requirements", "Scheduled maintenance tasks"],
    response: ["Immediately alert Tier 2 analyst", "Review user's recent activity timeline", "Disable account pending investigation", "Capture memory if host supports it"],
    category: "Endpoint",
  },
  {
    id: "SR-004",
    name: "Ransomware File Extension Pattern",
    severity: "CRITICAL",
    tactic: "Impact",
    technique: "T1486",
    techniqueURL: "https://attack.mitre.org/techniques/T1486/",
    description: "Identifies mass file modification events where files are renamed with known ransomware extensions or where entropy analysis suggests encryption activity.",
    logic: 'event.type == "file" AND file.extension IN ransomware_ext_list AND count(file.modified) > 100 WITHIN 5m',
    falsePositives: ["Backup software during archiving", "Compression tools processing large datasets"],
    response: ["ISOLATE HOST IMMEDIATELY", "Preserve disk image for forensics", "Identify patient zero — check lateral movement", "Activate IR runbook", "Notify management and legal"],
    category: "Endpoint",
  },
  {
    id: "SR-005",
    name: "Suspicious PowerShell Execution",
    severity: "HIGH",
    tactic: "Execution",
    technique: "T1059.001",
    techniqueURL: "https://attack.mitre.org/techniques/T1059/001/",
    description: "Detects PowerShell processes launched with encoded commands, download cradles, or execution policy bypass flags — common in fileless malware and post-exploitation frameworks.",
    logic: 'process.name == "powershell.exe" AND process.args MATCHES "-enc|-nop|-w hidden|DownloadString|IEX|Invoke-Expression"',
    falsePositives: ["Legitimate IT management scripts", "Windows Update internals"],
    response: ["Capture and decode the base64 payload", "Check parent process lineage", "Search for persistence mechanisms", "Hunt across fleet for same command hash"],
    category: "Endpoint",
  },
  {
    id: "SR-006",
    name: "Data Exfiltration via DNS",
    severity: "HIGH",
    tactic: "Exfiltration",
    technique: "T1048.003",
    techniqueURL: "https://attack.mitre.org/techniques/T1048/003/",
    description: "Detects anomalously large DNS query volumes, unusually long subdomain strings, or high-entropy subdomains consistent with DNS tunneling or covert exfiltration channels.",
    logic: 'dns.query.length > 100 OR count(dns.queries) > 500 WITHIN 10m OR entropy(dns.subdomain) > 3.5',
    falsePositives: ["CDN providers with long subdomains", "Internal split-horizon DNS resolution"],
    response: ["Block DNS queries to flagged domain", "Capture DNS traffic for analysis", "Identify source process making queries", "Check for C2 infrastructure matches"],
    category: "Network",
  },
  {
    id: "SR-007",
    name: "Lateral Movement via SMB",
    severity: "HIGH",
    tactic: "Lateral Movement",
    technique: "T1021.002",
    techniqueURL: "https://attack.mitre.org/techniques/T1021/002/",
    description: "Identifies abnormal SMB authentication patterns — a single source authenticating to multiple hosts rapidly, consistent with worm propagation or attacker pivoting through a network.",
    logic: 'event.type == "smb_auth" AND count(distinct dest.host) > 5 WITHIN 10m AND source.host == same',
    falsePositives: ["Domain controllers during replication", "IT asset management agents"],
    response: ["Map the lateral movement path", "Identify the origin host", "Reset credentials for all affected accounts", "Check for persistence on each touched host"],
    category: "Network",
  },
  {
    id: "SR-008",
    name: "New Admin Account Created",
    severity: "MEDIUM",
    tactic: "Persistence",
    technique: "T1136.001",
    techniqueURL: "https://attack.mitre.org/techniques/T1136/001/",
    description: "Triggers when a new local administrator account is created outside of approved provisioning workflows, particularly on servers or outside business hours.",
    logic: 'event.type == "user_created" AND user.group == "Administrators" AND NOT source.process IN approved_provisioning_tools',
    falsePositives: ["IT help desk provisioning new users", "Automated onboarding workflows"],
    response: ["Verify with HR/IT if account is authorized", "Disable account pending verification", "Audit who created the account and from where", "Review all actions taken by new account"],
    category: "Identity",
  },
  {
    id: "SR-009",
    name: "C2 Beacon Pattern",
    severity: "CRITICAL",
    tactic: "Command and Control",
    technique: "T1071.001",
    techniqueURL: "https://attack.mitre.org/techniques/T1071/001/",
    description: "Detects highly regular outbound HTTP/S connections at fixed intervals to a single external IP, consistent with C2 beaconing behavior from implants like Cobalt Strike or Metasploit.",
    logic: 'event.type == "network" AND dest.ip.is_external == true AND stddev(connection.interval) < 5s AND count(connections) > 20 WITHIN 30m',
    falsePositives: ["Telemetry agents with fixed reporting intervals", "NTP sync traffic"],
    response: ["Block outbound connection at firewall", "Capture full packet capture for IOC extraction", "Identify process responsible for connection", "Submit C2 IP to threat intel platform", "Assume host is compromised — begin IR"],
    category: "Network",
  },
  {
    id: "SR-010",
    name: "Credential Dumping — LSASS Access",
    severity: "CRITICAL",
    tactic: "Credential Access",
    technique: "T1003.001",
    techniqueURL: "https://attack.mitre.org/techniques/T1003/001/",
    description: "Detects processes attempting to open a handle to LSASS memory — the primary method used by tools like Mimikatz, ProcDump, and Cobalt Strike to extract NTLM hashes and Kerberos tickets.",
    logic: 'event.type == "process_access" AND target.process == "lsass.exe" AND access.rights CONTAINS "PROCESS_VM_READ"',
    falsePositives: ["AV/EDR solutions performing integrity checks", "Windows Error Reporting"],
    response: ["CRITICAL — assume credential compromise", "Force password reset across domain", "Check for pass-the-hash or pass-the-ticket activity", "Review all privileged account logins in last 24h"],
    category: "Endpoint",
  },
  {
    id: "SR-011",
    name: "Impossible Travel Login",
    severity: "HIGH",
    tactic: "Initial Access",
    technique: "T1078",
    techniqueURL: "https://attack.mitre.org/techniques/T1078/",
    description: "Flags authentication events where the same account logs in from two geographically distant locations within a time window that makes physical travel impossible.",
    logic: 'event.type == "auth_success" AND geo.distance(prev.login.location, current.login.location) > 500km AND time.delta < 60m',
    falsePositives: ["VPN endpoints appearing in different regions", "Proxy services and Tor exit nodes"],
    response: ["Force MFA re-authentication", "Temporarily suspend session", "Contact user out-of-band to verify", "Check if VPN or proxy explains discrepancy"],
    category: "Identity",
  },
  {
    id: "SR-012",
    name: "Scheduled Task Created",
    severity: "MEDIUM",
    tactic: "Persistence",
    technique: "T1053.005",
    techniqueURL: "https://attack.mitre.org/techniques/T1053/005/",
    description: "Detects creation of new scheduled tasks that execute scripts, binaries, or encoded commands — a common persistence mechanism used by malware and post-exploitation frameworks.",
    logic: 'event.type == "task_created" AND task.action MATCHES ("powershell|cmd|wscript|cscript|rundll32") AND NOT task.author IN approved_task_list',
    falsePositives: ["Legitimate software installers", "IT automation tools like Ansible or SCCM"],
    response: ["Review the task action and trigger", "Check the binary or script it executes", "Search for the task across fleet", "Delete if unauthorized and trace origin process"],
    category: "Endpoint",
  },
  {
    id: "SR-013",
    name: "Outbound Connection to TOR Exit Node",
    severity: "HIGH",
    tactic: "Exfiltration",
    technique: "T1090.003",
    techniqueURL: "https://attack.mitre.org/techniques/T1090/003/",
    description: "Flags any outbound network connection to a known TOR exit node IP, which may indicate anonymized exfiltration, C2 communication, or policy violation.",
    logic: 'event.type == "network" AND dest.ip IN tor_exit_node_list AND direction == "outbound"',
    falsePositives: ["Security researchers", "Privacy-conscious employees using Tor Browser"],
    response: ["Block connection and alert user", "Determine application making the connection", "Review recent file access on the source host", "Escalate — TOR usage on corp network is high-risk signal"],
    category: "Network",
  },
];

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#FF3B5C", bg: "rgba(255,59,92,0.12)", label: "CRITICAL" },
  HIGH:     { color: "#FF8C42", bg: "rgba(255,140,66,0.12)", label: "HIGH" },
  MEDIUM:   { color: "#F5C518", bg: "rgba(245,197,24,0.12)", label: "MEDIUM" },
  LOW:      { color: "#4CAF50", bg: "rgba(76,175,80,0.12)", label: "LOW" },
};

const CATEGORIES = ["All", "Network", "Endpoint", "Authentication", "Identity"];
const SEVERITIES = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

// ─── SIMULATED LIVE EVENTS ───────────────────────────────────────────────────

const EVENT_TEMPLATES = [
  { rule: "SR-002", host: "192.168.1.47", severity: "MEDIUM" },
  { rule: "SR-001", host: "WIN-DC01", severity: "HIGH" },
  { rule: "SR-005", host: "DESKTOP-A3X9", severity: "HIGH" },
  { rule: "SR-009", host: "192.168.1.102", severity: "CRITICAL" },
  { rule: "SR-013", host: "LAPTOP-HR04", severity: "HIGH" },
  { rule: "SR-008", host: "WIN-SRV02", severity: "MEDIUM" },
  { rule: "SR-010", host: "DESKTOP-B7K1", severity: "CRITICAL" },
  { rule: "SR-011", host: "user@corp.com", severity: "HIGH" },
];

function generateEvent(id) {
  const tmpl = EVENT_TEMPLATES[Math.floor(Math.random() * EVENT_TEMPLATES.length)];
  const rule = DETECTION_RULES.find(r => r.id === tmpl.rule);
  return {
    id,
    ruleId: tmpl.rule,
    ruleName: rule.name,
    host: tmpl.host,
    severity: tmpl.severity,
    tactic: rule.tactic,
    technique: rule.technique,
    time: new Date(),
    status: "NEW",
  };
}

// ─── COMPONENTS ─────────────────────────────────────────────────────────────

function SeverityBadge({ severity, small }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.LOW;
  return (
    <span style={{
      background: cfg.bg,
      color: cfg.color,
      border: `1px solid ${cfg.color}40`,
      borderRadius: 4,
      padding: small ? "2px 7px" : "3px 10px",
      fontSize: small ? 10 : 11,
      fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      letterSpacing: "0.08em",
      whiteSpace: "nowrap",
    }}>
      {cfg.label}
    </span>
  );
}

function CategoryBadge({ cat }) {
  const colors = {
    Network: "#00B4D8", Endpoint: "#7B61FF",
    Authentication: "#FF8C42", Identity: "#F5C518",
  };
  const c = colors[cat] || "#888";
  return (
    <span style={{
      background: `${c}18`, color: c,
      border: `1px solid ${c}40`,
      borderRadius: 4, padding: "2px 8px",
      fontSize: 10, fontWeight: 600,
      fontFamily: "'JetBrains Mono', monospace",
      letterSpacing: "0.06em",
    }}>
      {cat}
    </span>
  );
}

function StatCard({ label, value, accent, sub }) {
  return (
    <div style={{
      background: "#0D1117",
      border: `1px solid ${accent}30`,
      borderTop: `2px solid ${accent}`,
      borderRadius: 8,
      padding: "20px 24px",
      flex: 1, minWidth: 140,
    }}>
      <div style={{ color: "#888", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", marginBottom: 8 }}>{label}</div>
      <div style={{ color: accent, fontSize: 32, fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ color: "#555", fontSize: 11, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function RuleCard({ rule, onClick, isSelected }) {
  const cfg = SEVERITY_CONFIG[rule.severity];
  return (
    <div
      onClick={() => onClick(rule)}
      style={{
        background: isSelected ? "#161B22" : "#0D1117",
        border: `1px solid ${isSelected ? cfg.color + "60" : "#21262D"}`,
        borderLeft: `3px solid ${cfg.color}`,
        borderRadius: 8,
        padding: "16px 18px",
        cursor: "pointer",
        transition: "all 0.15s ease",
        marginBottom: 8,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
            <span style={{ color: "#4A9EFF", fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{rule.id}</span>
            <CategoryBadge cat={rule.category} />
          </div>
          <div style={{ color: "#E6EDF3", fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{rule.name}</div>
          <div style={{ color: "#888", fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>
            {rule.tactic} · <span style={{ color: "#4A9EFF" }}>{rule.technique}</span>
          </div>
        </div>
        <SeverityBadge severity={rule.severity} />
      </div>
    </div>
  );
}

function RuleDetail({ rule, onClose }) {
  const cfg = SEVERITY_CONFIG[rule.severity];
  return (
    <div style={{
      background: "#0D1117",
      border: `1px solid #21262D`,
      borderTop: `2px solid ${cfg.color}`,
      borderRadius: 8,
      padding: "24px",
      height: "100%",
      overflowY: "auto",
      boxSizing: "border-box",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
            <span style={{ color: "#4A9EFF", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{rule.id}</span>
            <SeverityBadge severity={rule.severity} />
            <CategoryBadge cat={rule.category} />
          </div>
          <h2 style={{ color: "#E6EDF3", fontSize: 18, fontWeight: 700, margin: 0 }}>{rule.name}</h2>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "1px solid #333", color: "#888", borderRadius: 4, padding: "4px 10px", cursor: "pointer", fontSize: 16 }}>✕</button>
      </div>

      <Section label="DESCRIPTION">
        <p style={{ color: "#C9D1D9", fontSize: 13, lineHeight: 1.7, margin: 0 }}>{rule.description}</p>
      </Section>

      <Section label="MITRE ATT&CK">
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <InfoPill label="Tactic" value={rule.tactic} />
          <InfoPill label="Technique" value={rule.technique} accent="#4A9EFF" />
        </div>
      </Section>

      <Section label="DETECTION LOGIC">
        <div style={{
          background: "#010409", border: "1px solid #21262D",
          borderRadius: 6, padding: "14px 16px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 12, color: "#58A6FF", lineHeight: 1.8,
          wordBreak: "break-all",
        }}>
          {rule.logic}
        </div>
      </Section>

      <Section label="RESPONSE PLAYBOOK">
        <ol style={{ margin: 0, paddingLeft: 20 }}>
          {rule.response.map((step, i) => (
            <li key={i} style={{
              color: i === 0 && step.startsWith("CRITICAL") ? "#FF3B5C" : "#C9D1D9",
              fontSize: 13, lineHeight: 1.7, marginBottom: 4,
              fontWeight: i === 0 && step.startsWith("CRITICAL") ? 700 : 400,
            }}>{step}</li>
          ))}
        </ol>
      </Section>

      <Section label="KNOWN FALSE POSITIVES">
        <ul style={{ margin: 0, paddingLeft: 20 }}>
          {rule.falsePositives.map((fp, i) => (
            <li key={i} style={{ color: "#8B949E", fontSize: 13, lineHeight: 1.7, marginBottom: 2 }}>{fp}</li>
          ))}
        </ul>
      </Section>
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        color: "#4A9EFF", fontSize: 10, fontFamily: "'JetBrains Mono', monospace",
        letterSpacing: "0.15em", fontWeight: 700, marginBottom: 10,
        borderBottom: "1px solid #21262D", paddingBottom: 6,
      }}>{label}</div>
      {children}
    </div>
  );
}

function InfoPill({ label, value, accent }) {
  return (
    <div style={{ background: "#161B22", border: "1px solid #21262D", borderRadius: 6, padding: "8px 14px" }}>
      <div style={{ color: "#555", fontSize: 10, letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", marginBottom: 3 }}>{label}</div>
      <div style={{ color: accent || "#E6EDF3", fontSize: 13, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
    </div>
  );
}

function EventFeed({ events }) {
  return (
    <div style={{ height: 340, overflowY: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
      {events.length === 0 && (
        <div style={{ color: "#555", fontSize: 12, textAlign: "center", padding: "40px 0", fontFamily: "'JetBrains Mono', monospace" }}>
          Waiting for events...
        </div>
      )}
      {events.map((ev, i) => {
        const cfg = SEVERITY_CONFIG[ev.severity];
        const isNew = i === 0;
        return (
          <div key={ev.id} style={{
            background: isNew ? `${cfg.color}08` : "#0D1117",
            border: `1px solid ${isNew ? cfg.color + "40" : "#21262D"}`,
            borderLeft: `3px solid ${cfg.color}`,
            borderRadius: 6, padding: "10px 14px",
            display: "flex", justifyContent: "space-between", alignItems: "center",
            gap: 8, flexWrap: "wrap",
            animation: isNew ? "fadeIn 0.4s ease" : "none",
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: "#E6EDF3", fontSize: 12, fontWeight: 600, marginBottom: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{ev.ruleName}</div>
              <div style={{ color: "#555", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
                {ev.host} · <span style={{ color: "#4A9EFF" }}>{ev.technique}</span>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
              <SeverityBadge severity={ev.severity} small />
              <span style={{ color: "#444", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
                {ev.time.toLocaleTimeString()}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────────────

export default function SentinelView() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [selectedRule, setSelectedRule] = useState(null);
  const [filterCategory, setFilterCategory] = useState("All");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [events, setEvents] = useState([]);
  const [eventCount, setEventCount] = useState(0);
  const [liveMode, setLiveMode] = useState(false);
  const intervalRef = useRef(null);
  const idRef = useRef(0);

  useEffect(() => {
    if (liveMode) {
      intervalRef.current = setInterval(() => {
        const ev = generateEvent(idRef.current++);
        setEvents(prev => [ev, ...prev].slice(0, 50));
        setEventCount(c => c + 1);
      }, 2200);
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [liveMode]);

  const filteredRules = DETECTION_RULES.filter(r => {
    const matchCat = filterCategory === "All" || r.category === filterCategory;
    const matchSev = filterSeverity === "All" || r.severity === filterSeverity;
    const matchSearch = !searchQuery || r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.technique.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.tactic.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchCat && matchSev && matchSearch;
  });

  const criticalCount = DETECTION_RULES.filter(r => r.severity === "CRITICAL").length;
  const highCount = DETECTION_RULES.filter(r => r.severity === "HIGH").length;
  const categoryCount = [...new Set(DETECTION_RULES.map(r => r.category))].length;
  const tacticCount = [...new Set(DETECTION_RULES.map(r => r.tactic))].length;

  const tabStyle = (tab) => ({
    background: "none", border: "none",
    borderBottom: activeTab === tab ? "2px solid #4A9EFF" : "2px solid transparent",
    color: activeTab === tab ? "#E6EDF3" : "#555",
    padding: "12px 20px", cursor: "pointer",
    fontSize: 13, fontWeight: 600,
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: "0.05em",
    transition: "all 0.15s",
  });

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');
        * { box-sizing: border-box; }
        body { margin: 0; background: #010409; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0D1117; }
        ::-webkit-scrollbar-thumb { background: #21262D; border-radius: 3px; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
      `}</style>

      <div style={{ minHeight: "100vh", background: "#010409", color: "#E6EDF3", fontFamily: "'Syne', sans-serif" }}>

        {/* HEADER */}
        <div style={{
          background: "#0D1117", borderBottom: "1px solid #21262D",
          padding: "0 24px", display: "flex", alignItems: "center",
          justifyContent: "space-between", height: 60, position: "sticky", top: 0, zIndex: 100,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 32, height: 32, background: "linear-gradient(135deg, #4A9EFF, #00B4D8)",
              borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 16,
            }}>🛡</div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 800, letterSpacing: "0.08em", color: "#E6EDF3", fontFamily: "'Bebas Neue', sans-serif", lineHeight: 1 }}>SENTINELVIEW</div>
              <div style={{ fontSize: 9, color: "#444", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em" }}>SOC ANALYST TRAINING PLATFORM</div>
            </div>
          </div>

          <nav style={{ display: "flex", gap: 0 }}>
            {[["dashboard", "DASHBOARD"], ["rules", "DETECTION RULES"], ["feed", "LIVE FEED"]].map(([tab, label]) => (
              <button key={tab} style={tabStyle(tab)} onClick={() => setActiveTab(tab)}>{label}</button>
            ))}
          </nav>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: liveMode ? "#4CAF50" : "#555",
              animation: liveMode ? "pulse 1.5s infinite" : "none",
            }} />
            <span style={{ color: liveMode ? "#4CAF50" : "#555", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
              {liveMode ? "LIVE" : "IDLE"}
            </span>
          </div>
        </div>

        <div style={{ maxWidth: 1400, margin: "0 auto", padding: "24px" }}>

          {/* ── DASHBOARD TAB ── */}
          {activeTab === "dashboard" && (
            <div>
              <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 28, fontWeight: 800, margin: "0 0 4px", fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em" }}>
                  Security Operations Dashboard
                </h1>
                <p style={{ color: "#555", fontSize: 13, margin: 0 }}>
                  13 active detection rules · MITRE ATT&CK aligned · SOC analyst training environment
                </p>
              </div>

              {/* STAT CARDS */}
              <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
                <StatCard label="TOTAL RULES" value={DETECTION_RULES.length} accent="#4A9EFF" sub="Active detection logic" />
                <StatCard label="CRITICAL" value={criticalCount} accent="#FF3B5C" sub="Immediate response required" />
                <StatCard label="HIGH SEVERITY" value={highCount} accent="#FF8C42" sub="Escalate within 1 hour" />
                <StatCard label="TACTICS COVERED" value={tacticCount} accent="#7B61FF" sub="MITRE ATT&CK tactics" />
                <StatCard label="CATEGORIES" value={categoryCount} accent="#00B4D8" sub="Network · Endpoint · Identity" />
              </div>

              {/* TACTIC COVERAGE */}
              <div style={{ background: "#0D1117", border: "1px solid #21262D", borderRadius: 8, padding: "20px 24px", marginBottom: 24 }}>
                <div style={{ color: "#4A9EFF", fontSize: 10, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.15em", fontWeight: 700, marginBottom: 16 }}>
                  MITRE ATT&CK TACTIC COVERAGE
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {[...new Set(DETECTION_RULES.map(r => r.tactic))].map(tactic => {
                    const rules = DETECTION_RULES.filter(r => r.tactic === tactic);
                    const hasCritical = rules.some(r => r.severity === "CRITICAL");
                    const hasHigh = rules.some(r => r.severity === "HIGH");
                    const accent = hasCritical ? "#FF3B5C" : hasHigh ? "#FF8C42" : "#F5C518";
                    return (
                      <div key={tactic} style={{
                        background: `${accent}10`, border: `1px solid ${accent}30`,
                        borderRadius: 6, padding: "8px 14px",
                      }}>
                        <div style={{ color: accent, fontSize: 11, fontWeight: 700, marginBottom: 2 }}>{tactic}</div>
                        <div style={{ color: "#555", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>{rules.length} rule{rules.length > 1 ? "s" : ""}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* CRITICAL RULES SPOTLIGHT */}
              <div style={{ background: "#0D1117", border: "1px solid #FF3B5C30", borderRadius: 8, padding: "20px 24px" }}>
                <div style={{ color: "#FF3B5C", fontSize: 10, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.15em", fontWeight: 700, marginBottom: 16 }}>
                  ⚠ CRITICAL SEVERITY RULES — IMMEDIATE RESPONSE REQUIRED
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {DETECTION_RULES.filter(r => r.severity === "CRITICAL").map(rule => (
                    <div key={rule.id} style={{
                      background: "#010409", border: "1px solid #FF3B5C20",
                      borderLeft: "3px solid #FF3B5C", borderRadius: 6, padding: "14px 16px",
                      cursor: "pointer",
                    }} onClick={() => { setSelectedRule(rule); setActiveTab("rules"); }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div>
                          <span style={{ color: "#4A9EFF", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, marginRight: 10 }}>{rule.id}</span>
                          <span style={{ color: "#E6EDF3", fontSize: 13, fontWeight: 600 }}>{rule.name}</span>
                        </div>
                        <span style={{ color: "#555", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{rule.technique}</span>
                      </div>
                      <p style={{ color: "#8B949E", fontSize: 12, margin: "6px 0 0", lineHeight: 1.5 }}>{rule.description.slice(0, 120)}...</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── RULES TAB ── */}
          {activeTab === "rules" && (
            <div>
              <div style={{ marginBottom: 20 }}>
                <h1 style={{ fontSize: 28, fontWeight: 800, margin: "0 0 4px", fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em" }}>
                  Detection Rules Library
                </h1>
                <p style={{ color: "#555", fontSize: 13, margin: "0 0 16px" }}>Click any rule to view detection logic, MITRE mapping, and response playbook.</p>

                {/* FILTERS */}
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <input
                    placeholder="Search rules, techniques, tactics..."
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    style={{
                      background: "#0D1117", border: "1px solid #21262D", borderRadius: 6,
                      padding: "8px 14px", color: "#E6EDF3", fontSize: 13,
                      fontFamily: "'JetBrains Mono', monospace", width: 280, outline: "none",
                    }}
                  />
                  <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)}
                    style={{ background: "#0D1117", border: "1px solid #21262D", borderRadius: 6, padding: "8px 12px", color: "#E6EDF3", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}>
                    {CATEGORIES.map(c => <option key={c}>{c}</option>)}
                  </select>
                  <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
                    style={{ background: "#0D1117", border: "1px solid #21262D", borderRadius: 6, padding: "8px 12px", color: "#E6EDF3", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}>
                    {SEVERITIES.map(s => <option key={s}>{s}</option>)}
                  </select>
                  <span style={{ color: "#555", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", marginLeft: 4 }}>
                    {filteredRules.length} / {DETECTION_RULES.length} rules
                  </span>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: selectedRule ? "1fr 1fr" : "1fr", gap: 20, alignItems: "start" }}>
                <div style={{ overflowY: selectedRule ? "auto" : "visible", maxHeight: selectedRule ? "80vh" : "none" }}>
                  {filteredRules.map(rule => (
                    <RuleCard key={rule.id} rule={rule} onClick={setSelectedRule} isSelected={selectedRule?.id === rule.id} />
                  ))}
                  {filteredRules.length === 0 && (
                    <div style={{ color: "#555", textAlign: "center", padding: "60px 0", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
                      No rules match your filters.
                    </div>
                  )}
                </div>
                {selectedRule && (
                  <div style={{ position: "sticky", top: 80 }}>
                    <RuleDetail rule={selectedRule} onClose={() => setSelectedRule(null)} />
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── LIVE FEED TAB ── */}
          {activeTab === "feed" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24, flexWrap: "wrap", gap: 16 }}>
                <div>
                  <h1 style={{ fontSize: 28, fontWeight: 800, margin: "0 0 4px", fontFamily: "'Bebas Neue', sans-serif", letterSpacing: "0.05em" }}>
                    Live Alert Feed
                  </h1>
                  <p style={{ color: "#555", fontSize: 13, margin: 0 }}>
                    Simulated real-time detection events · {eventCount} events generated
                  </p>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                  <button
                    onClick={() => setLiveMode(v => !v)}
                    style={{
                      background: liveMode ? "#FF3B5C15" : "#4CAF5015",
                      border: `1px solid ${liveMode ? "#FF3B5C" : "#4CAF50"}`,
                      color: liveMode ? "#FF3B5C" : "#4CAF50",
                      borderRadius: 6, padding: "8px 18px",
                      cursor: "pointer", fontSize: 12, fontWeight: 700,
                      fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.06em",
                    }}
                  >
                    {liveMode ? "⏹ STOP" : "▶ START SIMULATION"}
                  </button>
                  <button
                    onClick={() => { setEvents([]); setEventCount(0); }}
                    style={{
                      background: "none", border: "1px solid #21262D",
                      color: "#555", borderRadius: 6, padding: "8px 14px",
                      cursor: "pointer", fontSize: 12, fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    CLEAR
                  </button>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16, marginBottom: 24 }}>
                {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => {
                  const count = events.filter(e => e.severity === sev).length;
                  return (
                    <div key={sev} style={{
                      background: "#0D1117", border: `1px solid ${cfg.color}30`,
                      borderTop: `2px solid ${cfg.color}`, borderRadius: 8, padding: "16px 20px",
                    }}>
                      <div style={{ color: "#888", fontSize: 10, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", marginBottom: 6 }}>{sev}</div>
                      <div style={{ color: cfg.color, fontSize: 28, fontFamily: "'Bebas Neue', sans-serif" }}>{count}</div>
                    </div>
                  );
                })}
              </div>

              <div style={{ background: "#0D1117", border: "1px solid #21262D", borderRadius: 8, padding: "20px 24px" }}>
                <div style={{ color: "#4A9EFF", fontSize: 10, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.15em", fontWeight: 700, marginBottom: 16 }}>
                  ALERT STREAM {liveMode && <span style={{ animation: "pulse 1s infinite", display: "inline-block", marginLeft: 8 }}>●</span>}
                </div>
                <EventFeed events={events} />
              </div>

              {!liveMode && events.length === 0 && (
                <div style={{ textAlign: "center", padding: "40px 0", color: "#444", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
                  Press START SIMULATION to generate live detection events.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
