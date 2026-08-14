<#
.SYNOPSIS
    Flags suspicious process creation events in
    logs/samples/process-events.csv - encoded PowerShell, LOLBin abuse,
    and unusual parent/child relationships.
    MITRE ATT&CK: T1059 - Command and Scripting Interpreter,
                  T1105 - Ingress Tool Transfer (certutil download pattern)
#>
param(
    [string]$LogPath = "logs\samples\process-events.csv"
)

$suspiciousParents = @("winword.exe","excel.exe","outlook.exe")
$lolbins            = @("certutil.exe","mshta.exe","regsvr32.exe","bitsadmin.exe")

$events = Import-Csv -Path $LogPath

$alerts = foreach ($e in $events) {
    $reasons = @()

    if ($e.CommandLine -match "-enc(odedcommand)?\s") { $reasons += "Encoded PowerShell command" }
    if ($suspiciousParents -contains $e.ParentImage)   { $reasons += "Office app spawned a shell/interpreter" }
    if ($lolbins -contains $e.Image)                   { $reasons += "Known LOLBin used ($($e.Image))" }
    if ($e.CommandLine -match "http[s]?://")            { $reasons += "Network download pattern in command line" }

    if ($reasons.Count -gt 0) {
        [pscustomobject]@{
            TimeCreated    = $e.TimeCreated
            Image          = $e.Image
            ParentImage    = $e.ParentImage
            CommandLine    = $e.CommandLine
            Reasons        = ($reasons -join "; ")
            MitreTechnique = "T1059 / T1105"
            Severity       = if ($reasons.Count -ge 2) { "High" } else { "Medium" }
        }
    }
}

if ($alerts) {
    Write-Host "ALERT: suspicious process activity detected" -ForegroundColor Red
    $alerts | Format-Table -AutoSize
    $alerts | Export-Csv -Path "logs\samples\process-alerts.csv" -NoTypeInformation
} else {
    Write-Host "No suspicious process patterns detected." -ForegroundColor Green
}
