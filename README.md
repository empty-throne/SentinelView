<div align="center">

# 🛡️ SentinelView

### SOC Analyst Training Dashboard

![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2023-F7DF1E?style=for-the-badge&logo=javascript)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Aligned-FF3B5C?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-00B4D8?style=for-the-badge)
![Rules](https://img.shields.io/badge/Detection%20Rules-13-7B61FF?style=for-the-badge)

*An interactive SOC analyst training platform featuring 13 real-world detection rules, full MITRE ATT&CK mappings, response playbooks, and a live alert simulation engine — built to demonstrate both defensive security knowledge and frontend engineering capability.*

**[▶ Live Demo](sentinel-view-l8m3.vercel.app)** · **[Portfolio](https://github.com/empty-throne)** · **[LinkedIn](www.linkedin.com/in/zackery-monk)**

</div>

---

## 📌 Overview

SentinelView is a **fully interactive SOC analyst training environment** built in React. It simulates the core workflow a Tier 1 analyst follows when triaging alerts in a SIEM — reviewing detection logic, understanding the MITRE ATT&CK technique behind an alert, and executing a structured response playbook.

The project was built to answer a critical question: *how do you demonstrate SOC readiness when you don't yet have enterprise SIEM experience?* The answer is to build the tooling yourself — and document the security reasoning behind every decision.

Every detection rule in this dashboard is grounded in real adversary behavior, mapped to a specific ATT&CK technique, and paired with a response playbook that mirrors what a Tier 1 or Tier 2 analyst would actually do.

---

## 🎯 Why I Built This

After 1,200+ job applications yielded minimal results, I audited my own portfolio and identified the gap: I could talk about security concepts, but had nothing that demonstrated I could *apply* them in an operational context.

SentinelView is the answer to that gap. It is not a tutorial follow-along. Every detection rule was researched, written, and documented from scratch — starting from the ATT&CK technique, working backwards to the detection logic, and then building the frontend to present it professionally.

The result is something that functions simultaneously as:
- A **portfolio piece** that demonstrates both security depth and engineering ability
- A **personal study tool** for practicing alert triage and technique identification
- A **reference library** for MITRE ATT&CK mappings during Security+ exam prep

---

## ⚙️ Technical Summary

| Property | Detail |
|---|---|
| **Framework** | React 18 with Hooks |
| **Language** | JavaScript (ES2023) |
| **Styling** | Inline CSS with CSS variables — zero external UI libraries |
| **State Management** | useState, useEffect, useRef (no Redux) |
| **Live Simulation** | setInterval-based event engine with randomized alert generation |
| **Fonts** | Bebas Neue (display) + JetBrains Mono (code/data) + Syne (body) |
| **Theme** | GitHub Dark-inspired security terminal aesthetic |
| **Deployment** | Vercel / Netlify (static, zero backend required) |

---

## 🔍 Feature Breakdown

### 1 — Security Operations Dashboard

The landing view gives a real-time operational picture:

- **Stat cards** — total rules, critical count, high severity count, tactic coverage, categories
- **MITRE ATT&CK Tactic Coverage** — visual grid of every tactic covered, color-coded by highest severity rule within that tactic
- **Critical Rules Spotlight** — immediate visibility into the three rules requiring the fastest response time

### 2 — Detection Rules Library (13 Rules)

The core of the platform. Every rule includes:

| Field | Description |
|---|---|
| **Rule ID** | Unique identifier (SR-001 through SR-013) |
| **Severity** | CRITICAL / HIGH / MEDIUM with color coding |
| **Category** | Network / Endpoint / Authentication / Identity |
| **MITRE Tactic** | The ATT&CK tactic phase the rule targets |
| **Technique ID** | Specific ATT&CK technique with clickable link |
| **Description** | Plain-English explanation of the threat |
| **Detection Logic** | Pseudo-SIEM query syntax (SPL/KQL-style) |
| **Response Playbook** | Ordered steps a Tier 1/2 analyst should take |
| **False Positives** | Known benign triggers that could cause noise |

**Filter and search** by category, severity, technique ID, tactic, or rule name.

### 3 — Live Alert Feed Simulator

A real-time event engine that:

- Generates randomized detection alerts every 2.2 seconds from the rule library
- Displays severity-bucketed counters (CRITICAL / HIGH / MEDIUM / LOW)
- Shows a scrolling alert stream with host, technique, severity, and timestamp
- Toggle on/off with a START/STOP control — mirrors the feel of watching a SIEM dashboard

---

## 🗂️ Detection Rules Reference

| ID | Rule Name | Severity | Tactic | ATT&CK |
|---|---|---|---|---|
| SR-001 | Brute Force Login Attempt | HIGH | Credential Access | T1110 |
| SR-002 | Port Scan Detected | MEDIUM | Reconnaissance | T1046 |
| SR-003 | Privilege Escalation via Sudo | HIGH | Privilege Escalation | T1548.003 |
| SR-004 | Ransomware File Extension Pattern | CRITICAL | Impact | T1486 |
| SR-005 | Suspicious PowerShell Execution | HIGH | Execution | T1059.001 |
| SR-006 | Data Exfiltration via DNS | HIGH | Exfiltration | T1048.003 |
| SR-007 | Lateral Movement via SMB | HIGH | Lateral Movement | T1021.002 |
| SR-008 | New Admin Account Created | MEDIUM | Persistence | T1136.001 |
| SR-009 | C2 Beacon Pattern | CRITICAL | Command and Control | T1071.001 |
| SR-010 | Credential Dumping — LSASS Access | CRITICAL | Credential Access | T1003.001 |
| SR-011 | Impossible Travel Login | HIGH | Initial Access | T1078 |
| SR-012 | Scheduled Task Created | MEDIUM | Persistence | T1053.005 |
| SR-013 | Outbound Connection to TOR Exit Node | HIGH | Exfiltration | T1090.003 |

---

## 🧠 Security Concepts Demonstrated

### ATT&CK Kill Chain Coverage

SentinelView's 13 rules cover **9 of the 14 MITRE ATT&CK tactics**, spanning the full attack lifecycle from initial access through impact:

```
Reconnaissance → Initial Access → Execution → Persistence →
Privilege Escalation → Credential Access → Discovery →
Lateral Movement → Command and Control → Exfiltration → Impact
```

### Detection Logic Patterns

The detection rules use four distinct logic patterns, mirroring real SIEM query approaches:

- **Threshold-based** — count of events exceeds N within time window (SR-001, SR-002, SR-006)
- **Behavioral** — deviation from baseline or impossible state (SR-011 impossible travel)
- **Signature** — specific string, extension, or IOC match (SR-004, SR-005, SR-013)
- **Process lineage** — parent-child process relationship analysis (SR-003, SR-005, SR-010)

### SOC Tier Alignment

Each rule's response playbook is calibrated to the appropriate SOC tier:

- **Tier 1 (Triage)** — confirm alert is real, apply initial containment, escalate
- **Tier 2 (Investigation)** — deep dive analysis, timeline reconstruction, hunt expansion
- **Tier 3 / IR** — CRITICAL rules (SR-004, SR-009, SR-010) escalate directly here

---

## 🚀 Getting Started

### Prerequisites

- Node.js 18+ and npm
- Any modern browser

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/SentinelView.git
cd SentinelView

# Install dependencies
npm install

# Start development server
npm run dev
```

Open `http://localhost:5173` in your browser.

### Build for Production

```bash
npm run build
npm run preview
```

### Deploy to Vercel (one command)

```bash
npx vercel --prod
```

---

## 📁 Project Structure

```
SentinelView/
├── README.md
├── package.json
├── vite.config.js
├── index.html
└── src/
    ├── main.jsx                 # React entry point
    ├── SentinelView.jsx         # Main app component (all logic + UI)
    └── data/
        └── rules.js             # Detection rules data (extracted for clarity)
```

> **Note:** The app is intentionally kept as a single-file component to make it easy to run as a React artifact or embed in a portfolio page. A production version would split into `/components`, `/data`, and `/hooks` directories.

---

## 📸 Screenshots

> *(Replace with actual screenshots — see Photography Guide below)*

| Dashboard | Rules Library | Live Feed |
|---|---|---|
| `screenshot-dashboard.png` | `screenshot-rules.png` | `screenshot-feed.png` |

### Screenshot Guide

To capture clean portfolio screenshots:
1. Open the app at `localhost:5173`
2. Use browser zoom at 90% for a clean full-view capture
3. **Dashboard tab** — capture the stat cards + tactic grid
4. **Rules tab** — click SR-010 (LSASS) to show a CRITICAL rule detail panel open
5. **Feed tab** — start the simulation, wait 15 seconds, then screenshot the populated alert stream

---

## 🔗 Related Projects

| Project | Description |
|---|---|
| [Simple Port Scanner](https://github.com/YOUR_USERNAME/simple-port-scanner) | Multi-threaded async TCP port scanner in C++ — the attacker's-eye-view of what generates SentinelView alerts |
| [File Metadata Analyzer](https://github.com/YOUR_USERNAME/file-metadata-analyzer) | Python DFIR tool for extracting and analyzing file metadata in forensic investigations |

> These three projects form a deliberate trilogy: **reconnaissance** (port scanner) → **detection** (SentinelView) → **forensics** (metadata analyzer). Together they span the full security workflow from attacker action to analyst response.

---

## 📈 Planned Extensions

- [ ] Persistent alert state with browser storage
- [ ] Analyst notes / annotation system per alert
- [ ] Sigma rule export format for each detection rule
- [ ] Dark/light theme toggle
- [ ] PCAP upload for manual event parsing
- [ ] Quiz mode — given an alert, select the correct ATT&CK technique

---

## 👤 About

**Zackery** — Cybersecurity professional transitioning into SOC analysis and penetration testing.
B.S. Cybersecurity (Cum Laude, 3.81 GPA) · CompTIA Security+ (in progress) · Charlotte, NC

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B6?style=flat&logo=linkedin)](www.linkedin.com/in/zackery-monk)
[![GitHub](https://img.shields.io/badge/GitHub-Portfolio-333?style=flat&logo=github)](https://github.com/empty-throne)

---

<div align="center">
<sub>Built with intent. Every rule researched. Every playbook written from scratch.</sub>
</div>
