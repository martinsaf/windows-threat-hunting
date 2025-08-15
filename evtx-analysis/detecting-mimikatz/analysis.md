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
  - `Huting_Mimikatz.evtx` - Obfuscated Mimikatz execution
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
Field              Value
---
**TimeStamp**      2021-01-05 03:22:52 (UTC)
**SourceImage**    `C:\Users\THM-Threat\Downloads\mimikatz.exe`
