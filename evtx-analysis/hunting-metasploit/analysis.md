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

### 1️⃣ Network Connection Analysis (Event ID 3)
`Findings`: Conection to 10.13.4.34:4444 via shell.exe
`MITRE Mapping`: (T1043 – Commonly Used Port)[https://attack.mitre.org/techniques/T1043/]
Port 4444 is often used by Meterpreter payloads for C2 communication.

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

### 📝 Follow-up investigation
Having identified the suspicious network activity, the next logical step is to pivot to process creation events (Event ID 1) to trace the execution chain and gather binary metadata.

---

## Process Creation Analysis (Event ID 1)

```powershell
# Correlating with process creation event for PID 3660
$ProcessId = 3660
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
            Hashes        = $data["Hashes"]
            ParentCommandLine = $data["ParentCommandLine"]
        }
    }
```

---

📌 Process Creation Findings
- Timestamp: 1/5/2021 2:21:29 AM
- CommandLine: .\shell.exe
- User: THM\THM-Threat
- ProcessPath: C:\Users\THM-Threat\Downloads\shell.exe
- Hashes:
```text
MD5=FC03EB95876A310DF9D63477F0ADDDFD,SHA256=84C5E6C0C6AF4C25DCD89362723A574D8514B5B88B25AF18750DA56
B497F8EA8,IMPHASH=481F47BBB2C9C21E108D65F52B04C448
```
- ParentCommandLine: "C:\Windows\system32\cmd.exe"
- ParentProcess : `(Not visible in logs)`

### 🧩 Enhanced Interpretation

1. Execution Context
   - Binary Origin:
     ```text
     ProcessPath: C:\Users\THM-Threat\Downloads\shell.exe  
     ```
   - Execution Method:
     ```text
     ParentCommandLine: "C:\Windows\system32\cmd.exe"  
     CommandLine: .\shell.exe  
     ```
     - Manual execution via command prompt (no automation/scheduler)
2. Binary Analysis (Directly From Your Data):
   - Hashing Evidence:
     ```text
     SHA256: 84C5E6C0C6AF4C25DCD89362723A574D8514B5B88B25AF18750DA56B497F8EA8  
     ```
     - Non-reputable hash (not found in VirusTotal/known software DBs)
   - Suspicious Metada:
     ```text
     (Implied from OriginalFileName in XML - though not explicitly shown in this output)  
     ```
3. Temporal analysis:
   - Process creation at 2:21:29 AM -> Network connection at 2:21:32 AM
     - 3-second delay matches staged payload behavior
4. Parent Process Gap:
   - Missing parent process details suggests:
     - Logging limitation OR
     - Direct user execution (no process injection)

--- 

2️⃣ Process Creation Analysis (Event ID 1)
`Findings`: Execução manual de C:\Users\THM-Threat\Downloads\shell.exe
`MITRE Mapping`: T1204.002 – User Execution: Malicious File

Malicious file executed by the user, likely delivered via phishing or web transfer.

3️⃣ Metadata & Masquerading Detection
`Findings`: Binário com metadados falsos (ApacheBench)
`MITRE Mapping`: T1036 – Masquerading

Changing attributes to disguise the true nature of the torque.

---

## 🛠️ Updated Hunting Script

```powershell
### Enhanced Hunting with Binary Analysis
$MaliciousHashes = @(
    "84C5E6C0C6AF4C25DCD89362723A574D8514B5B88B25AF18750DA56B497F8EA8",
    "FC03EB95876A310DF9D63477F0ADDDFD"
)
```
`Purpose`: Defines known malicious hashes from your earlier findings to hunt for related activity.

---

## Part 1: Detect Binaries with Mismatched Metadata
```powershell
# 1. Detect binaries with mismatched metadata
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath '*/System/EventID=1' |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = @{}
        $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        
        if ($data["Image"] -match "Downloads\\" -and 
            ($data["Company"] -match "Apache" -or $data["Description"] -match "ApacheBench")) {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                ProcessName = $data["Image"]
                OriginalName = $data["OriginalFileName"]
                Company = $data["Company"]
                Hashes = $data["Hashes"]
            }
        }
    }
```
### What This does:
1. Search all process creation events (Event ID 1)
2. Looks for executables:
   - Located in Downloads folder
   - With metadata claiming to be from "Apache" or "ApacheBench"
  
3. Returns:
   - Execution timestamp
   - Actual process path
   - Original filename from metadata
   - Company name from metada
   - File hashes

---

## Part 2: Cross-Reference with Network Connections
```powershell
# 2. Cross-reference with network connections
$MaliciousHashes | ForEach-Object {
    Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath '*/System/EventID=1' |
        Where-Object { $_.Message -match $_ } |
        ForEach-Object {
            $pid = ([xml]$_.ToXml()).Event.EventData.Data | 
                   Where-Object { $_.Name -eq "ProcessId" } | 
                   Select-Object -ExpandProperty "#text"
            
            Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath "*/System/EventID=3 and */EventData/Data[@Name='ProcessId']='$pid'"
        }
}
```
### What This Does:
1. For each known malicious hash:
   - Finds matching process creation events
   - Extracts the ProcessID
   - Searches for network connections (Event ID 3) from that same ProcessID
  
---

# Key Improvements Over Original Script:
1. Two-Part Hunting:
   - First finds suspicious binaries by metadata patterns.
   - Then correlates them with network activity
2. Flexible Detection:
   - Uses both hashes AND behavioral patterns (Downloads folder + Apache metadata)
3. MITRE Technique Mapping:
```text
T1036 - Masquerading (metadata mismatch)
T1043 - Commonly Used Port (4444)
T1204 - User Execution (Downloads folder)
```

---

## 📌 MITRE ATT&CK Mapping

| Step | Finding | MITRE Technique | Description |
|------|---------|-----------------|-------------|
| **1** | Network connection from `shell.exe` to 10.13.4.34:4444 | [T1043 – Commonly Used Port](https://attack.mitre.org/techniques/T1043/) | Port 4444 is often used by Meterpreter payloads for C2 communication. |
| **2** | Manual execution of `C:\Users\THM-Threat\Downloads\shell.exe` | [T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) | Malicious executable run by the user, likely delivered via phishing or web download. |
| **3** | Binary metadata claims “ApacheBench” | [T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/) | Altered file attributes used to disguise malicious code as legitimate software. |

---

## 🚑 Response Recommendations
- Block IOC hashes in EDR
- Isolate host and capture volatile memory
- Search across enterprise for similar port 4444 connections
