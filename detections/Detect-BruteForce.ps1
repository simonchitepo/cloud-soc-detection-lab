<#
.SYNOPSIS
    Detects brute-force auth activity in logs/samples/auth-failures.csv.
    Rule: >= $Threshold failed logons from the same SourceIp within
    $WindowMinutes minutes = alert.
    MITRE ATT&CK: T1110 - Brute Force
#>
param(
    [string]$LogPath = "logs\samples\auth-failures.csv",
    [int]$Threshold = 5,
    [int]$WindowMinutes = 5
)

$events = Import-Csv -Path $LogPath | ForEach-Object {
    $_.TimeCreated = [datetime]$_.TimeCreated
    $_
}

$alerts = $events |
    Group-Object SourceIp |
    Where-Object { $_.Count -ge $Threshold } |
    ForEach-Object {
        $group = $_.Group | Sort-Object TimeCreated
        $span = ($group[-1].TimeCreated - $group[0].TimeCreated).TotalMinutes
        if ($span -le $WindowMinutes -or $group.Count -ge $Threshold) {
            [pscustomobject]@{
                SourceIp       = $_.Name
                FailedAttempts = $_.Count
                WindowMinutes  = [math]::Round($span,2)
                TargetUsers    = ($group.TargetUser | Select-Object -Unique) -join ","
                MitreTechnique = "T1110 - Brute Force"
                Severity       = if ($_.Count -ge 10) { "High" } else { "Medium" }
            }
        }
    }

if ($alerts) {
    Write-Host "ALERT: possible brute-force activity detected" -ForegroundColor Red
    $alerts | Format-Table -AutoSize
    $alerts | Export-Csv -Path "logs\samples\brute-force-alerts.csv" -NoTypeInformation
} else {
    Write-Host "No brute-force pattern detected." -ForegroundColor Green
}
