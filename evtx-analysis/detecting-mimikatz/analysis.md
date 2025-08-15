# Detecting Mimikatz - Threat Hunting Analysis

## 📝 Objective
Detect credential dumping activity from Mimikatz by identifying suspicious LSASS process access events using Sysmon logs and PowerShell.

---

## 🔍 Approach
We focused on detecting abnormal access to the **Local Security Authority Subsystem Service (lsass.exe)** process.
While antivirus solutions can detect default Mimikatz binaries, attackers may use obfuscated builds or rename executables to evade signature-based detection.
Behavior-based detection using Sysmon Event `10` (Process Access) allows us to catch such activity.

---

## 📁 Dataset
- Files:
  - `Hunting_Mimikatz.evtx` - Obfuscated Mimikatz execution
- Event Source: Sysmon
- Tool used: `Get-WinEvent` with XPath queries

--- 

## 🛠️ Hunting Query

```powershell
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx `
-FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"' |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }
        [PSCustomObject]@{
            TimeCreated   = $_.TimeCreated
            SourceImage   = $data["SourceImage"]
            TargetImage   = $data["TargetImage"]
            GrantedAccess = $data["GrantedAccess"]
            CallTrace     = $data["CallTrace"]
            ProcessId     = $data["ProcessId"]
        }
    }
```

## 📌 Key Findings
- **Timestamp**: 1/5/2021 3:22:52 AM
- **SourceImage**: C:\Users\THM-Threat\Downloads\mimikatz.exe
- **TargetImage**: C:\Windows\system32\lsass.exe
- **GrantedAccess**: 0x1010 `(PROCESS_VM READ | PROCESS_QUERY_INFORMATION)`
- **CallTrace**: `(indicators of direct LSASS memory access)`
    - C:\Windows\SYSTEM32\ntdll.dll+9f644|C:\Windows\System32\KERNELBASE.dll+212ae|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+bcbda|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+bcfb1|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+bcb19|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+84f28|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+84d60|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+84a93|
    - C:\Users\THM-Threat\Downloads\mimikatz.exe+c39a9|
    - C:\Windows\System32\KERNEL32.DLL+17974|
    - C:\Windows\SYSTEM32\ntdll.dll+5a0b1
- **ProcessId**: `(Not visible in logs)`

---

## Interpretation
The evidence shows that `mimikatz.exe`, executed from the `Downloads` directory, accessed `lsass.exe` with read and query permissions.
The `CallTrace` clearly shows function calls from both `ntdll.dll` and `KERNELBASE.dll` into the malicious process memory space, a strong indicator of credential dumping activity.
The absence of a visible ProcessId in the logs limits direct correlation to process creation events, but the binary path and access pattern match known Mimikatz behavior.

--- 

## 🔗 MITRE ATT&CK

- [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [S0002 — Mimikatz](https://attack.mitre.org/software/S0002/)

---

### 1️⃣ LSASS Access Analysis (Event ID 10)
**Findings**: `mimikatz.exe` accessed `lsass.exe` with read/query permissions (`0x1010`).
**MITRE Mapping**: [T1003.001](https://attack.mitre.org/techniques/T1003/001/) - Reading LSASS memory to extract credentials.

---

### ✅ `hunting.ps1` — Scripts

```powershell
### hunting Mimikatz via LSASS Access Events (Sysmon Event ID 10)

# Step 1: Identify Event ID 10 entries targeting LSASS
Get-WinEvent -Path ".\Hunting_Mimikatz.evtx" `
-FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"]="C:\Windows\system32\lsass.exe"' |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }
        [PSCustomObject]@{
            TimeCreated   = $_.TimeCreated
            SourceImage   = $data["SourceImage"]
            TargetImage   = $data["TargetImage"]
            GrantedAccess = $data["GrantedAccess"]
            CallTrace     = $data["CallTrace"]
        }
    }
```
### Output:
```mathematica
TimeCreated   : 1/5/2021 3:22:52 AM
SourceImage   : C:\Users\THM-Threat\Downloads\mimikatz.exe
TargetImage   : C:\Windows\system32\lsass.exe
GrantedAccess : 0x1010
CallTrace     : C:\Windows\SYSTEM32\ntdll.dll+9f644|C:\Windows\System32\KERNELBASE.dll+212ae|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcbda|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcfb1|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcb19|C:\Users\THM-Threat\Downloads\mimikatz.exe+84f28|C:\Users\THM-Threat\Downloads\mimikatz.exe+84d60|C:\Users\THM-Threat\Downloads\mimikatz.exe+84a93|C:\Users\THM-Threat\Downloads\mimikatz.exe+c39a9|C:\Windows\System32\KERNEL32.DLL+17974|C:\Windows\SYSTEM32\ntdll.dll+5a0b1
```

---

## Get Sysmon Event 
```powershell
PS C:\Users\THM-Analyst> Get-WinEvent -Path  C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx |
     Where-Object { $_.Id -eq 10 -and $_.ToXml().Contains("lsass.exe") } |
     ForEach-Object { $_.ToXml()
}
```

## 🗂 Raw Sysmon Event (XML)
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>
    <EventID>10</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>10</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2021-01-05T03:22:52.589622600Z'/>
    <EventRecordID>51901</EventRecordID>
    <Correlation/>
    <Execution ProcessID='1376' ThreadID='6928'/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>THM-SOC-DC01.thm.soc</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='RuleName'>-</Data>
    <Data Name='UtcTime'>2021-01-05 03:22:52.581</Data>
    <Data Name='SourceProcessGUID'>{6cd1ea62-db8c-5ff3-8b07-00000000f500}</Data>
    <Data Name='SourceProcessId'>3604</Data>
    <Data Name='SourceThreadId'>4292</Data>
    <Data Name='SourceImage'>C:\Users\THM-Threat\Downloads\mimikatz.exe</Data>
    <Data Name='TargetProcessGUID'>{6cd1ea62-b769-5fef-0c00-00000000f500}</Data>
    <Data Name='TargetProcessId'>744</Data>
    <Data Name='TargetImage'>C:\Windows\system32\lsass.exe</Data>
    <Data Name='GrantedAccess'>0x1010</Data>
    <Data Name='CallTrace'>C:\Windows\SYSTEM32\ntdll.dll+9f644|C:\Windows\System32\KERNELBASE.dll+212ae|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcbda|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcfb1|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcb19|C:\Users\THM-Threat\Downloads\mimikatz.exe+84f28|C:\Users\THM-Threat\Downloads\mimikatz.exe+84d60|C:\Users\THM-Threat\Downloads\mimikatz.exe+84a93|C:\Users\THM-Threat\Downloads\mimikatz.exe+c39a9|C:\Windows\System32\KERNEL32.DLL+17974|C:\Windows\SYSTEM32\ntdll.dll+5a0b1</Data>
  </EventData>
</Event>
```

---

# Event Correlation
Extracted Data from Event ID 10

|          Field          |      Value      
|-------------------------|-------------------------------------------------------------------------|
|  **TimeStamp**          |    2021-01-05 03:22:52 (UTC)                                            |
|-------------------------|-------------------------------------------------------------------------|
|  **SourceImage**        |    `C:\Users\THM-Threat\Downloads\mimikatz.exe`                         |
|-------------------------|-------------------------------------------------------------------------|
|  **SourceProcessId**    |    3604                                                                 |
|-------------------------|-------------------------------------------------------------------------|
|  **TargetImage**        |    `C:\Windows\system32\lsass.exe`                                      |
|-------------------------|-------------------------------------------------------------------------|
|  **TargetProcessId**    |    744                                                                  |
|-------------------------|-------------------------------------------------------------------------|
|  **GrantedAccess**      |    `0x1010` (PROCESS_VM_READ)                                           |
|-------------------------|-------------------------------------------------------------------------|
|  **CallTrace**          |    `ntdll.dll`, `KERNELBASE.dll`, internal functions of `mimikatz.exe`  |
|-------------------------|-------------------------------------------------------------------------|

### Analysis:
- The **mimikatz.exe** process was executed from the user's **Downloads** folder, a common location for manually introduced binaries.
- Attempted **read/query** to the **LSASS** process (PID 744), which stores credentials in memory.
- The `CallTrace` shows a chain of calls through **ntdll.dll** and **KERNELBASE.dll**, consistent with direct memory access.
- The `GrantedAccess` value `0x1010` aligns with typical *credentials dumping.* attempts using Mimikatz.

---

### 🛡️ Threat Mapping
**MITRE ATT&CK**:
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **Software ID**: S0002 (Mimikatz)
**Indicators**:
- Execution of Mimikatz binary (even if unsigned or renamed).
- Direct LSASS access with read/query permissions.
- Suspicious call trace indicating memory manipulation.

---

# 🔗 Correlating Mimikatz Execution (Sysmon Event ID 1)
**Objective**: Link the `SourceProcessId` (3604) from the Event ID 10 (LSASS access) to its process creation event to gather full execution context (command line, parent process, user, etc.).

---

### Command to run:
```powershell
# Find process creation event for SourceProcessId 3604
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" `
| Where-Object { $_.Id -eq 1 -and $_.ToXml().Contains("3604") } `
| ForEach-Object { $_.ToXml() }
```

---

### 🔗 Execution Context Analysis (Sysmon Event ID 1)
**Key Details from Process Creation Event**:
- **ProcessId**: 3604
- **Process GUID**: `{6cd1ea62-db8c-5ff3-8b07-00000000f500}`
- **Image**: `C:\Users\THM-Threat\Downloads\mimikatz.exe`
- **Command Line**: `.\mimikatz privilege::debug sekurlsa::logonpasswords`
- **Parent Process**: `C:\Windows\System32\cmd.exe` (PID 8092)
- **User**: `THM\THM-Threat`
- **Integrity Level**: High
- **Hashes**:
    - MD5: `A3CB3B02A683275F7E0A0F8A9A5C9E07`
    - SHA256: `31EB1DE7E840A342FD468E558E5AB627BCB4C542A8FE01AEC4D5BA01D539A0FC`
- **Original File Name**: `mimikatz.exe`
- **Description / Product / Company**: `mimikatz for Windows / mimikatz / gentilkiwi (Benjamin DELPY)`

**Interpretation**:
- The attacker executed `mimikatz.exe` from a user directory with **high integrity privileges**, likely after elevating via `privilege::debug`.
- Parent process is `cmd.exe`, which suggests manual execution or script-driven execution.
- The hashconfirm this is a known Mimikatz binary.
    -  [trojan.mimikatz/marte](https://www.virustotal.com/gui/file/31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc)

---

### Next Step: Extract Logon Session Details
**Objective**: Identify which logon sessions were targeted and what credentials were dumped.

---

### Command to run:
```powershell
# Extract Mimikatz-related logon password dumps from Event ID 10 CallTrace
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" `
| Where-Object { $_.Id -eq 10 -and $_.ToXml().Contains("lsass.exe") } `
| ForEach-Object {
    [xml]$xml = $_.ToXml()
    $xml.Event.EventData.Data | ForEach-Object {
        if ($_.Name -eq "CallTrace") { $_.'#text' }
    }
}
```

**Results**:
```mathematica
# Extract Mimikatz-related logon password dumps from Event ID 10 CallTrace

C:\Windows\SYSTEM32\ntdll.dll+9f644|C:\Windows\System32\KERNELBASE.dll+212ae|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcbda|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcfb1|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcb19|C:\Users\THM-Threat\Downloads\mimikatz.exe+84f28|C:\Users\THM-Threat\Downloads\mimikatz.exe+84d60|C:\Users\THM-Threat\Downloads\mimikatz.exe+84a93|C:\Users\THM-Threat\Downloads\mimikatz.exe+c39a9|C:\Windows\System32\KERNEL32.DLL+17974|C:\Windows\SYSTEM32\ntdll.dll+5a0b1
```

We have the **CallTrace** confirming `mimikatz.exe` interacted with lsass.exe.
This shows the tool attempted **credential dumping** from the Local Security Authority Subsystem Service (LSASS).

---

### Next step: Map the LSASS access to user logon sessions
We want to find the TargetProcessId (744) and cross-reference it **logon sessions**. This will help us see **which accounts were potentially compromised**.

---
### Command to run:
```powershell
# Find logon session events related to TargetProcessId 744
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" `
| Where-Object { $_.Id -eq 10 -and $_.ToXml().Contains("TargetProcessId'>744") } `
| ForEach-Object { $_.ToXml() }
```

**Results**:
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>
    <EventID>10</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>10</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2021-01-05T03:22:52.589622600Z'/>
    <EventRecordID>51901</EventRecordID>
    <Correlation/>
    <Execution ProcessID='1376' ThreadID='6928'/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>THM-SOC-DC01.thm.soc</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='RuleName'>-</Data>
    <Data Name='UtcTime'>2021-01-05 03:22:52.581</Data>
    <Data Name='SourceProcessGUID'>{6cd1ea62-db8c-5ff3-8b07-00000000f500}</Data>
    <Data Name='SourceProcessId'>3604</Data>
    <Data Name='SourceThreadId'>4292</Data>
    <Data Name='SourceImage'>C:\Users\THM-Threat\Downloads\mimikatz.exe</Data>
    <Data Name='TargetProcessGUID'>{6cd1ea62-b769-5fef-0c00-00000000f500}</Data>
    <Data Name='TargetProcessId'>744</Data>
    <Data Name='TargetImage'>C:\Windows\system32\lsass.exe</Data>
    <Data Name='GrantedAccess'>0x1010</Data>
    <Data Name='CallTrace'>C:\Windows\SYSTEM32\ntdll.dll+9f644|C:\Windows\System32\KERNELBASE.dll+212ae|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcbda|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcfb1|C:\Users\THM-Threat\Downloads\mimikatz.exe+bcb19|C:\Users\THM-Threat\Downloads\mimikatz.exe+84f28|C:\Users\THM-Threat\Downloads\mimikatz.exe+84d60|C:\Users\THM-Threat\Downloads\mimikatz.exe+84a93|C:\Users\THM-Threat\Downloads\mimikatz.exe+c39a9|C:\Windows\System32\KERNEL32.DLL+17974|C:\Windows\SYSTEM32\ntdll.dll+5a0b1</Data>
  </EventData>
</Event>
```

This confirms **TargetProcessId 744 is** ``lsass.exe, and the `CallTrace` shows the Mimikatz execution chain.

---

### Next Step: Identify the user accounts loaded in LSASS at the time
We need Event ID 4624 (Logon) to correlate which accounts were active in the session Mimikatz targeted.

---

**Command to run**:
```powershell
# Find logon events around the timestamp of Mimikatz execution
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" `
| Where-Object { $_.Id -eq 4624 -and $_.TimeCreated -ge (Get-Date "2021-01-05T03:20:00Z") -and $_.TimeCreated -le (Get-Date "2021-01-05T03:25:00Z") } `
| ForEach-Object { $_.ToXml() }
```

**No results from command above**, it seems there were no 4624 events in that EVTX file during that window. That's actually common in **Sysmon-only EVTX captures**, since 4624 is a **Windows Security log event**, not a Sysmon event.

---

### Next Step: Extract parent-child process relationships to see how Mimikatz was launched
We already `mimikatz.exe` (PID 3604) was spawned by cmd.exe (PID 8092). Let's confirm all process launched by that cmd.exe session.

---

### Command to run:

```powershell
# List processes spawned by parent PID 8092
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" `
| Where-Object { $_.Id -eq 1 -and $_.ToXml().Contains("ParentProcessId'>8092") } `
| ForEach-Object { $_.ToXml() }
```

`PID 3604`
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}' />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2021-01-05T03:22:52.497682900Z' />
    <EventRecordID>51900</EventRecordID>
    <Correlation />
    <Execution ProcessID='1376' ThreadID='6928' />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>THM-SOC-DC01.thm.soc</Computer>
    <Security UserID='S-1-5-18' />
  </System>
  <EventData>
    <Data Name='RuleName'>MitreRef=T1036,Technique=Masquerading,Tactic=Defense Evasion/Execution</Data>
    <Data Name='UtcTime'>2021-01-05 03:22:52.491</Data>
    <Data Name='ProcessGuid'>{6cd1ea62-db8c-5ff3-8b07-00000000f500}</Data>
    <Data Name='ProcessId'>3604</Data>
    <Data Name='Image'>C:\Users\THM-Threat\Downloads\mimikatz.exe</Data>
    <Data Name='FileVersion'>2.2.0.0</Data>
    <Data Name='Description'>mimikatz for Windows</Data>
    <Data Name='Product'>mimikatz</Data>
    <Data Name='Company'>gentilkiwi (Benjamin DELPY)</Data>
    <Data Name='OriginalFileName'>mimikatz.exe</Data>
    <Data Name='CommandLine'>.\mimikatz  privilege::debug sekurlsa::logonpasswords</Data>
    <Data Name='CurrentDirectory'>C:\Users\THM-Threat\Downloads\</Data>
    <Data Name='User'>THM\THM-Threat</Data>
    <Data Name='LogonGuid'>{6cd1ea62-c19e-5fef-f30c-450000000000}</Data>
    <Data Name='LogonId'>0x450cf3</Data>
    <Data Name='TerminalSessionId'>4</Data>
    <Data Name='IntegrityLevel'>High</Data>
    <Data Name='Hashes'>MD5=A3CB3B02A683275F7E0A0F8A9A5C9E07,SHA256=31EB1DE7E840A342FD468E558E5AB627BCB4C542A8FE01AEC4D5BA01D539A0FC,IMPHASH=DBDEA7B557F0E6B5D9E18ABE9CE5220A</Data>
    <Data Name='ParentProcessGuid'>{6cd1ea62-db3a-5ff3-8807-00000000f500}</Data>
    <Data Name='ParentProcessId'>8092</Data>
    <Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data>
    <Data Name='ParentCommandLine'>"C:\Windows\system32\cmd.exe" </Data>
  </EventData>
</Event>
```

`PID 6596`
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}' />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2021-01-05T03:22:09.250805200Z' />
    <EventRecordID>51875</EventRecordID>
    <Correlation />
    <Execution ProcessID='1376' ThreadID='6928' />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>THM-SOC-DC01.thm.soc</Computer>
    <Security UserID='S-1-5-18' />
  </System>
  <EventData>
    <Data Name='RuleName'>MitreRef=T1036,Technique=Masquerading,Tactic=Defense Evasion/Execution</Data>
    <Data Name='UtcTime'>2021-01-05 03:22:09.221</Data>
    <Data Name='ProcessGuid'>{6cd1ea62-db61-5ff3-8a07-00000000f500}</Data>
    <Data Name='ProcessId'>6596</Data>
    <Data Name='Image'>C:\Users\THM-Threat\Downloads\mimikatz.exe</Data>
    <Data Name='FileVersion'>2.2.0.0</Data>
    <Data Name='Description'>mimikatz for Windows</Data>
    <Data Name='Product'>mimikatz</Data>
    <Data Name='Company'>gentilkiwi (Benjamin DELPY)</Data>
    <Data Name='OriginalFileName'>mimikatz.exe</Data>
    <Data Name='CommandLine'>.\mimikatz  privilege::debug; sekurlsa::logonpasswords</Data>
    <Data Name='CurrentDirectory'>C:\Users\THM-Threat\Downloads\</Data>
    <Data Name='User'>THM\THM-Threat</Data>
    <Data Name='LogonGuid'>{6cd1ea62-c19e-5fef-f30c-450000000000}</Data>
    <Data Name='LogonId'>0x450cf3</Data>
    <Data Name='TerminalSessionId'>4</Data>
    <Data Name='IntegrityLevel'>High</Data>
    <Data Name='Hashes'>MD5=A3CB3B02A683275F7E0A0F8A9A5C9E07,SHA256=31EB1DE7E840A342FD468E558E5AB627BCB4C542A8FE01AEC4D5BA01D539A0FC,IMPHASH=DBDEA7B557F0E6B5D9E18ABE9CE5220A</Data>
    <Data Name='ParentProcessGuid'>{6cd1ea62-db3a-5ff3-8807-00000000f500}</Data>
    <Data Name='ParentProcessId'>8092</Data>
    <Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data>
    <Data Name='ParentCommandLine'>"C:\Windows\system32\cmd.exe" </Data>
  </EventData>
</Event>
```

### Results:
This confirms the process tree for `cmd.exe` (PID 8092):
- **Parent**: `cmd.exe` (PID 8092)
- **Children**: Two instances of `mimikatz.exe`
    - PID 3604 → `.\mimikatz privilege::debug sekurlsa::logonpasswords`
    - PID 6596 → `.\mimikatz privilege::debug; sekurlsa::logonpasswords`
 
Both executions were run under the user `THM\Threat` in session 4, with **high integrity**. the timestamps show:
- PID 6596: `2021-01-05 03:22:09`
- PID 3604: `2021-01-05 03:22:52`

This is consistent with `Mimikatz being executed twice in quick sucession`, likely for password extraction from `lsass.exe`.
The **Sysmon Event ID 10** you retrieved earlier confirms the **TargetProcessId 744** (`lsass.exe`) was accessed by PID 3604, which matches the second Mimikatz execution.

---

### Process Tree Around PID 8092
```yaml
[PID 8092] cmd.exe (Parent)
     ├── [PID 6596] mimikatz.exe
     │       CommandLine: .\mimikatz privilege::debug; sekurlsa::logonpasswords
     │       User: THM\THM-Threat
     │       Integrity: High
     │       Time: 2021-01-05 03:22:09 UTC
     └── [PID 3604] mimikatz.exe
             CommandLine: .\mimikatz privilege::debug sekurlsa::logonpasswords
             User: THM\THM-Threat
             Integrity: High
             Time: 2021-01-05 03:22:52 UTC
```

---

### Key Points:
1. **Parent Process (cmd.exe PID 8092)**
  - Likely an interactive command prompt session opened by the user THM-Threat.
2. **Child Processes (Mimikatz executions)**
  - Two separate Mimikatz executions within ~43 seconds.
  - High integrity level indicates administrative privileges, which is required for credential dumping.
  - Both attempts use sekurlsa::logonpasswords to extract credentials from LSASS.
3. Security Implication
  - This is a clear indicator of credential theft, possibly for lateral movement or privilege escalation.
  - Mimikatz executed under the same logon session, meaning any compromised credentials belong to that session.
