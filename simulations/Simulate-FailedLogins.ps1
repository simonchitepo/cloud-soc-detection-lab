<#
.SYNOPSIS
    Generates synthetic authentication-failure log entries (like a
    brute-force attempt) into logs/samples/auth-failures.csv.
    This is SAFE - it does not touch real Windows accounts, it just
    writes log-shaped data so we have something to detect against.
#>
param(
    [int]$AttackerAttempts = 12,
    [string]$AttackerIp = "203.0.113.55",
    [string]$TargetUser = "administrator"
)

$rows = @()
$start = Get-Date

for ($i = 0; $i -lt $AttackerAttempts; $i++) {
    $rows += [pscustomobject]@{
        TimeCreated = $start.AddSeconds($i * 3)
        EventId     = 4625                 # Windows: failed logon
        SourceIp    = $AttackerIp
        TargetUser  = $TargetUser
        LogonType   = 3                    # network logon
        Outcome     = "FAILURE"
    }
}

# sprinkle in a few normal/legit failed logins for noise
$rows += [pscustomobject]@{
    TimeCreated = $start.AddMinutes(5)
    EventId     = 4625
    SourceIp    = "10.0.0.15"
    TargetUser  = "simon"
    LogonType   = 2
    Outcome     = "FAILURE"
}

$rows | Export-Csv -Path "logs\samples\auth-failures.csv" -NoTypeInformation -Append
Write-Host "Wrote $($rows.Count) simulated auth events to logs\samples\auth-failures.csv"
