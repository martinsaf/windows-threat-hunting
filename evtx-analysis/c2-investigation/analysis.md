# Investigation 1 - Malicious USB Activity Analysis

## 📝 Objective
Identify malicious USB device activity and trace the execution chain of payloads delivered via removable storage.

---

## 🔍 Approach
We focused on analyzing Sysmon events related to USB device interactions, process creations, and registry modifications to identify the initial infection vector and payloads execution.

---

## 📁 Dataset
- **File:** `Investigation-1.evtx`
- **Event Source:** Sysmon
- **Relevant Event IDs:** 1 (Process Create), 12/13 (Registry), 9 (RawAccessRead)
- **Tool used:** `Get-WinEvent` with PowerShell filtering

---

## 🛠️ Hunting Query

```powershell
# Initial exploration of event types
Get-WinEvent -Path ".\Investigation-1.evtx" | Group-Object Id
```

### Output:
```text
Count Name                      Group
----- ----                      -----
    1 5                         {System.Diagnostics.Eventing.Reader.EventLogRecord}
    3 1                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Read...
    4 9                         {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Read...
    2 13                        {System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Read...
    1 3                         {System.Diagnostics.Eventing.Reader.EventLogRecord}
```

## 📊 Event Distribution:
- ID 1 (Process Create): 3 events
- ID 3 (Network Connection): 1 event
- ID 5 (Process Terminated): 1 event
- ID 9 (RawAccessRead): 4 events
- ID 13 (Registry Value Set): 2 events

---

# 🔎 Registry Analysis (Event ID 13)

## 🛠️ Hunting Query:

```powershell
Get-WinEvent -Path ".\Investigation-1.evtx" |
Where-Object { $_.Id -eq 13 } |
Select-Object -ExpandProperty Message
```

## 📋 Findings:
Two registry modifications were detected:

1. USB Device Registration:
```text
Image: HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName
```

2. Portable Device Configuration:
```text
Image: HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\WPDBUSENUMROOT#UMB#2&37C186B&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName

```

## 🧩 Interpretation:
- **Malicious USB Device Identified**: Sandish Cruzer Micro
- **Serial Number**: 4054910EF19005B3
- **Registry Persistence**: Device registered in both `Enum\WpdBusEnumRoot` and portable devices configuration
- **Execution Trigger**: `FriendlyName` value potentially used for automatic execution

# ✅ Key Answer:
Full registry key of USB device:

```text
HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#
```













