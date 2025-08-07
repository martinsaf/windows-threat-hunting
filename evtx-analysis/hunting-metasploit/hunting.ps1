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
