# Splunk Queries - Phishing Investigation

All SPL queries used during the detection and investigation phase.

---

## 1. Broad Hunt - All 4688 Events (Excluding Splunk Noise)

**Purpose:** Initial wide search to see all process creation events without Splunk internal noise.

```spl
index=* EventCode=4688
| where Creator_Process_Name!="E:\\splunk forwarder\\bin\\splunkd.exe"
AND Creator_Process_Name!="C:\\Program Files\\Splunk\\bin\\splunkd.exe"
| table _time, user, New_Process_Name, Creator_Process_Name
| sort _time
```

---

## 2. Suspicious Parent Process Hunt

**Purpose:** Narrow down to processes spawned by cmd.exe, powershell.exe, or explorer.exe - the core detection query used to find the attack chain.

```spl
index=* EventCode=4688
| where Creator_Process_Name="C:\\Windows\\System32\\cmd.exe"
OR Creator_Process_Name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
OR Creator_Process_Name="C:\\Windows\\explorer.exe"
| where NOT New_Process_Name LIKE "%splunk%"
AND NOT New_Process_Name LIKE "%btool%"
AND NOT New_Process_Name LIKE "%conda%"
| table _time, user, New_Process_Name, Creator_Process_Name
| sort _time
```

---

## 3. Persistence Detection - reg.exe Activity

**Purpose:** Identify any registry modifications made by cmd.exe - used to confirm the persistence phase of the attack.

```spl
index=* EventCode=4688
| where New_Process_Name="C:\\Windows\\System32\\reg.exe"
| table _time, user, New_Process_Name, Creator_Process_Name
| sort _time
```

---

## 4. Recon Detection - Native Windows Tools

**Purpose:** Identify execution of common recon binaries spawned by cmd.exe.

```spl
index=* EventCode=4688
| where New_Process_Name IN (
    "C:\\Windows\\System32\\whoami.exe",
    "C:\\Windows\\System32\\ipconfig.exe",
    "C:\\Windows\\System32\\net.exe",
    "C:\\Windows\\System32\\systeminfo.exe"
)
| table _time, user, New_Process_Name, Creator_Process_Name
| sort _time
```

---

## 5. C2 Detection - PowerShell Spawned by cmd.exe

**Purpose:** Identify PowerShell being launched by cmd.exe - indicator of C2 beaconing or script-based payload execution.

```spl
index=* EventCode=4688
| where New_Process_Name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
AND Creator_Process_Name="C:\\Windows\\System32\\cmd.exe"
| table _time, user, New_Process_Name, Creator_Process_Name
| sort _time
```

---

## 6. Full Attack Chain - Single Query

**Purpose:** Capture the complete attack chain in one view. The primary query saved as a Splunk report.

```spl
index=* EventCode=4688
| where New_Process_Name="C:\\Windows\\System32\\cmd.exe"
OR New_Process_Name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
OR Creator_Process_Name="C:\\Windows\\System32\\cmd.exe"
OR Creator_Process_Name="C:\\Windows\\explorer.exe"
| table _time, user, New_Process_Name, Creator_Process_Name
| sort _time
```

---

## Notes

- All queries use `index=*` - in a production environment replace with the specific index name (e.g. `index=windows`)
- Time filtering should be applied via the Splunk time picker rather than hardcoded in the query - Splunk stores timestamps in UTC which can cause mismatches with hardcoded local time values
- These queries were saved as a report in Splunk under the name **"Suspicious Process Chain - Event 4688"**
```
