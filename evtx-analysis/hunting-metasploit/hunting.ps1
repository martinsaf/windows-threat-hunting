<#
.SYNOPSIS
    Hunting Metasploit artifacts in Windows Event Logs
.DESCRIPTION
    Analyzes Sysmon logs for suspicious network connections (Event ID 3) to common Metasploit ports
.NOTES
    File Name      : hunting.ps1
    Author         : YourName
    Prerequisite   : PowerShell 5.1+, Sysmon logs
#>

### 🕵️‍♂️ Hunting Metasploit - Network Connections Analysis

# 1. First show all available event IDs in the log
Write-Host "`n[+] Analyzing Event IDs in Hunting_Metasploit.evtx..." -ForegroundColor Cyan
Get-WinEvent -Path ".\Hunting_Metasploit.evtx" |
    Group-Object Id |
    Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

# 2. Filter network connections to common Metasploit ports (4444, 5555, etc.)
Write-Host "`n[+] Checking for suspicious network connections..." -ForegroundColor Cyan
$suspiciousPorts = @(4444, 5555, 8080) # Common Metasploit ports

foreach ($port in $suspiciousPorts) {
    Write-Host "`nChecking port $port..." -ForegroundColor Yellow
    
    try {
        $events = Get-WinEvent -Path ".\Hunting_Metasploit.evtx" -FilterXPath "*[System[EventID=3]] and *[EventData[Data[@Name='DestinationPort']=$port]]" -ErrorAction Stop
        
        if ($events.Count -gt 0) {
            $events | ForEach-Object {
                [xml]$xml = $_.ToXml()
                [PSCustomObject]@{
                    TimeCreated     = $_.TimeCreated
                    SourceIP        = $xml.Event.EventData.Data[3].'#text'
                    DestinationIP   = $xml.Event.EventData.Data[5].'#text'
                    DestinationPort = $xml.Event.EventData.Data[6].'#text'
                    ProcessName     = $xml.Event.EventData.Data[9].'#text'
                    ProcessID       = $xml.Event.EventData.Data[10].'#text'
                    User           = $xml.Event.EventData.Data[11].'#text'
                }
            } | Format-Table -AutoSize
        }
        else {
            Write-Host "No connections found on port $port" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Warning "Error processing port $port : $_"
    }
}

Write-Host "`n[+] Analysis complete`n" -ForegroundColor Green
