# Hunting Metasploit Activity (Sysmon)

## 📝 Objective

Detect network connections associated with Metasploit payloads using Sysmon logs and PowerShell.

## 🔍 Approach

We focused on identifying network connections to suspicious ports (e.g., 4444, 5555) commonly used by Metasploit payloads. We filtered Sysmon Event ID `3` (NetworkConnect) and extracted relevant metadata from the logs.

## 📁 Dataset

File: `Hunting_Metasploit.evtx`
Event Source: Sysmon
Tool used: `Get-WinEvent` with XPath

## 🛠️ Hunting Query

```powershell
Get-WinEvent -Path "Hunting_Metasploit.evtx" ` -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
```
## 📌 Key Findings
- Timestamp: 2021-01-05 02:21:32
- Destination Port: 4444
- Process ID: 1696
- Process Name: C:\Users\THM-Analyst\Downloads\shell.exe
- Destination IP: 192.168.49.128

## 🧠 Reflection

This technique can detect common Metasploit payloads, but port-based detection alone is limited. Future improvements include correlating this with `ProcessCreate` events to track process lineage.

## 🔗 MITRE ATT&CK

[T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
[S0002 - Metasploit](https://attack.mitre.org/software/S0002/)

### ✅ `hunting.ps1` — Scripts

```powershell
# Hunting Metasploit - Network connections to suspicious ports
# Sysmon Event ID 3

# Show all available event IDs in the log
Get-WinEvent -Path ".\Hunting_Metasploit.evtx" |
    Group-Object Id |
    Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

# Filter only network connections to port 4444
Get-WinEvent -Path ".\Hunting_Metasploit.evtx" -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444' |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        [PSCustomObject]@{
            TimeCreated     = $_.TimeCreated
            SourceIP        = $xml.Event.EventData.Data[3].'#text'
            DestinationIP   = $xml.Event.EventData.Data[5].'#text'
            DestinationPort = $xml.Event.EventData.Data[6].'#text'
            Image           = $xml.Event.EventData.Data[9].'#text'
            ProcessID       = $xml.Event.EventData.Data[10].'#text'
        }
    }
```
