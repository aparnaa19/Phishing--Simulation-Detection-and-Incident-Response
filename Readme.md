
# Phishing Simulation, Detection and Incident Response

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Attacker OS](https://img.shields.io/badge/Attacker-Ubuntu%2024-red)
![Event ID](https://img.shields.io/badge/Event%20ID-4688-purple)
![Kill Chain](https://img.shields.io/badge/Framework-Cyber%20Kill%20Chain-darkblue)
![License](https://img.shields.io/badge/License-Educational%20Use%20Only-lightgrey)

---

## Overview

This project is a full end-to-end simulation of a phishing attack, built in a home lab environment to practice real-world SOC analyst workflows. The project covers three distinct phases — building and delivering a realistic phishing attack, detecting it through behavioral log analysis, and documenting the findings as a formal SOC incident report.

The attack was designed to simulate techniques used by real threat actors — including email filter bypass using password-protected archives, Living off the Land (LotL) reconnaissance using native Windows binaries, registry-based persistence via masquerading, and C2 communication using a reverse TCP connection. No specialized malware frameworks were used — the entire payload was built from scratch using a Windows batch script and PowerShell.

Detection was performed entirely through behavioral analysis — hunting for suspicious parent-child process relationships in Splunk using Windows Event ID 4688. The payload had zero antivirus detections on VirusTotal, demonstrating that signature-based AV alone is insufficient against custom or novel threats.

---

## What This Project Covers

| Area | Detail |
|---|---|
| Attack Simulation | Phishing email crafting, payload development, social engineering |
| Email Security | DKIM, DMARC, SPF analysis — MXToolbox |
| Endpoint Logging | Windows audit policy, Event ID 4688 process creation logging |
| SIEM Analysis | Splunk SPL queries, process chain hunting, saved reports |
| Threat Techniques | Recon, persistence, C2, exfiltration, masquerading, LotL |
| Malware Analysis | SHA256 hashing, VirusTotal reputation check |
| Incident Response | Full SOC-style incident report with IOCs, timeline, and recommendations |

---

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM — detection and process chain analysis |
| Windows Event ID 4688 | Process creation logging |
| MXToolbox | Email header and authentication analysis |
| VirusTotal | Payload hash reputation check |
| netcat | C2 listener on attacker machine |
| Microsoft Outlook | Phishing email delivery |
| PowerShell | Payload C2 beacon |
| auditpol | Windows audit policy configuration |
| Ubuntu 24 (VirtualBox) | Attacker machine |
| Windows 11 | Victim machine |

---

## Lab Setup
┌─────────────────────┐         Bridged Network        ┌─────────────────────┐
│   Ubuntu VM         │◄──────────────────────────────►│   Windows Laptop    │
│   (Attacker)        │                                 │   (Victim)          │
│   192.168.0.24      │                                 │   192.168.0.14      │
│                     │                                 │                     │
│   - swaks           │                                 │   - Splunk          │
│   - netcat          │                                 │   - Event Viewer    │
│   - payload craft   │                                 │   - Outlook         │
└─────────────────────┘                                 └─────────────────────┘

---

## Attack Flow (Cyber Kill Chain)

Delivery       →  Phishing email with password-protected zip attachment
Execution      →  Victim runs invoice_report.bat → cmd.exe spawned
Recon          →  whoami, systeminfo, ipconfig, net user, net localgroup
Persistence    →  Registry Run key added (WindowsUpdater) — masquerading
C2             →  PowerShell reverse TCP connection to 192.168.0.24:4444
Exfiltration   →  System data transmitted to attacker over C2 channel


---

## Key Findings

- A custom payload with zero antivirus signatures successfully bypassed all email filters and endpoint protection
- Password-protected zip attachments bypass email content scanners — a widely used real-world technique
- The entire kill chain from execution to exfiltration completed in under 5 seconds
- Behavioral detection via Splunk (Event ID 4688) was the only effective control — traditional AV failed completely
- The attacker used native Windows tools exclusively (LotL) — no foreign binaries were introduced to the system
- Registry masquerading (`WindowsUpdater`) made persistence difficult to spot without cross-referencing known legitimate startup entries

---

## Project Structure

phishing-simulation-detection-ir/
│
├── README.md
│
├── docs/
│   ├── 01-simulation.md          ← How the attack was built and delivered
│   ├── 02-detection.md           ← How the attack was detected and investigated
│   └── 03-incident-report.md     ← Full SOC-style incident report
│
├── screenshots/                  ← All evidence screenshots referenced in docs
│
├── payloads/
│   └── invoice_report.bat        ← Simulated malicious payload
│
└── splunk-queries/
└── queries.md                ← All SPL queries used during investigation

---

## Documentation

| Document | Description |
|---|---|
| [Simulation](docs/01-simulation.md) | Step by step walkthrough of how the attack was built and delivered |
| [Detection](docs/02-detection.md) | How the attack was hunted and identified using Splunk and Event ID 4688 |
| [Incident Report](docs/03-incident-report.md) | Full SOC-style incident report with timeline, IOCs, and recommendations |

---

> All activities were conducted in a controlled home lab environment for educational purposes only. No real systems or individuals were targeted.
