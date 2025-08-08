# Hunting Metasploit Activity (Sysmon)

## 📝 Objective

Detect network connections associated with Metasploit payloads using Sysmon logs and PowerShell.

---

## 🔍 Approach

We focused on identifying network connections to suspicious ports (e.g., 4444, 5555) commonly used by Metasploit payloads. We filtered Sysmon Event ID `3` (NetworkConnect) and extracted relevant metadata from the logs.

---

## 📁 Dataset

- File: `Hunting_Metasploit.evtx`
- Event Source: Sysmon
- Tool used: `Get-WinEvent` with XPath

---

## 🛠️ Hunting Query

```powershell
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444' |
     ForEach-Object {
         [xml]$xml = $_.ToXml()
         $data = @{}
         foreach ($d in $xml.Event.EventData.Data) {
             $data[$d.Name] = $d.'#text'
         }
         [PSCustomObject]@{
             TimeCreated       = $_.TimeCreated
             SourceIP          = $data["SourceIp"]
             SourcePort        = $data["SourcePort"]
             DestinationIP     = $data["DestinationIp"]
             DestinationPort   = $data["DestinationPort"]
             Protocol          = $data["Protocol"]
             Image             = $data["Image"]
            ProcessId         = $data["ProcessId"]
         }
 }
```

---

## 📌 Key Findings
- Timestamp: 1/5/2021 2:21:32 AM
- Destination Port: 4444
- Destination IP: 10.13.4.34
- Source IP: 10.10.98.207
- Source Port: 50872
- Process ID: 3660
- Process Image: C:\Users\THM-Analyst\Downloads\shell.exe
- Protocol: TCP

---

## 🧩 Interpretation
The process `shell.exe`, executed from the Downloads folder, initiated a network connection to port `4444`, which is commonly associated with Metasploit reverse shells. This behavior is highly suspicious and likely indicates Meterpreter activity.

---

## 🔗 MITRE ATT&CK

[T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
[S0002 - Metasploit](https://attack.mitre.org/software/S0002/)

---

### ✅ `hunting.ps1` — Scripts

```powershell
### Hunting Metasploit - Network connections to suspicious ports
### Using Sysmon Event ID 3

# Step 1: List all Event IDs found in the log file
# Helps us understand what types of activity are recorded
Get-WinEvent -Path ".\Hunting_Metasploit_1609814643558.evtx" |
    Group-Object Id |
    Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

# Step 2: Hunt for connections to suspicious ports (e.g. 4444 - commonly used by Metasploit)
# This filters only Event ID 3 (network connections) and where the destination port is 4444
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444' |
     ForEach-Object {
         [xml]$xml = $_.ToXml()
         $data = @{}
         foreach ($d in $xml.Event.EventData.Data) {
             $data[$d.Name] = $d.'#text'
         }
         [PSCustomObject]@{
             TimeCreated       = $_.TimeCreated
             SourceIP          = $data["SourceIp"]
             SourcePort        = $data["SourcePort"]
             DestinationIP     = $data["DestinationIp"]
             DestinationPort   = $data["DestinationPort"]
             Protocol          = $data["Protocol"]
             Image             = $data["Image"]
            ProcessId         = $data["ProcessId"]
         }
 }
```

---

## ✅ Conclusion
This activity shows typical Metasploit behavior involving a reverse shell payload connecting back on port 4444. The executable path, port usage, and timing all point to a likely post-exploitation action. Follow-up investigation and response are recommended.

---

## Process Creation Analysis (Event ID 1)

```powershell
# Correlating with process creation event for PID 3360
$ProcessId = 3360
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath "*/System/EventID=1 and */EventData/Data[@Name='ProcessId']='$ProcessId'" |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }
        [PSCustomObject]@{
            Timestamp     = $_.TimeCreated
            CommandLine   = $data["CommandLine"]
            ParentProcess = $data["ParentProcessName"]
            User          = $data["User"]
            ProcessPath   = $data["Image"]
        }
    }
```

---

📌 Process Creation Findings
- Timestamp: 1/5/2021 2:21:29 AM
- CommandLine: .\shell.exe
- User: THM\THM-Threat
- ProcessPath: C:\Users\THM-Threat\Downloads\shell.exe
- ParentProcess : `(Not visible in logs)`

--- 🧩 Enhanced Interpretation

The process creation event reveals that:
1. The binary was executed directly from the Downloads folder (common infection vector)
2. No parent was logged (suggesting direct execution by user or log limitation)
3. The 3-second gap between execution and network connection matches typical Metasploit payload behavior

--- 🛠️ Updated Hunting Script

```powershell

```

---

📌 Enhanced Key Findings



