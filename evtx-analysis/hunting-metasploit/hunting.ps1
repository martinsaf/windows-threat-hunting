### Hunting Metasploit - Sysmon Event Analysis
### Description: Detects suspicious network activity (e.g. Metasploit reverse shells) and correlates with process creation events.

# Step 1: List all Event IDs in the log
Get-WinEvent -Path ".\Hunting_Metasploit_1609814643558.evtx" |
    Group-Object Id |
    Sort-Object Count -Descending |
    Format-Table Count, Name -AutoSize

# Step 2: Filter network connections to suspicious ports (e.g., 4444)
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx `
    -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444' |
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

# Step 3: Correlate network connections with process creation events (Event ID 1)
$ProcessId = 3660
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx `
    -FilterXPath "*/System/EventID=1 and */EventData/Data[@Name='ProcessId']='$ProcessId'" |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }
        [PSCustomObject]@{
            Timestamp          = $_.TimeCreated
            CommandLine        = $data["CommandLine"]
            ParentProcess      = $data["ParentProcessName"]
            User               = $data["User"]
            ProcessPath        = $data["Image"]
            Hashes             = $data["Hashes"]
            ParentCommandLine  = $data["ParentCommandLine"]
        }
    }

# Step 4: Detect binaries with suspicious metadata (Masquerading)
Get-WinEvent -Path .\Hunting_Metasploit_1609814643558.evtx -FilterXPath '*/System/EventID=1' |
    ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = @{}
        $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        
        if ($data["Image"] -match "Downloads\\" -and 
            ($data["Company"] -match "Apache" -or $data["Description"] -match "ApacheBench")) {
            [PSCustomObject]@{
                TimeCreated  = $_.TimeCreated
                ProcessName  = $data["Image"]
                OriginalName = $data["OriginalFileName"]
                Company      = $data["Company"]
                Hashes       = $data["Hashes"]
            }
        }
    }

# Step 5: Cross-reference malicious hashes with network activity
$MaliciousHashes = @(
    "84C5E6C0C6AF4C25DCD89362723A574D8514B5B88B25AF18750DA56B497F8EA8",
    "FC03EB95876A310DF9D63477F0ADDDFD"
)

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
