<#
.SYNOPSIS
    Runs a port scan against localhost only (127.0.0.1) and logs the
    results. Scanning machines you do not own/have permission to test
    is illegal in most jurisdictions - this script intentionally only
    targets your own loopback address.
#>
param(
    [string]$Target = "127.0.0.1",
    [int[]]$Ports = (20..25) + (80,135,139,443,445,3389,8080)
)

$results = foreach ($port in $Ports) {
    $test = Test-NetConnection -ComputerName $Target -Port $port -WarningAction SilentlyContinue
    [pscustomobject]@{
        TimeCreated = Get-Date
        SourceIp    = "203.0.113.55"   # simulated scanning host
        TargetIp    = $Target
        Port        = $port
        Open        = $test.TcpTestSucceeded
    }
}

$results | Export-Csv -Path "logs\samples\portscan.csv" -NoTypeInformation
Write-Host "Wrote port scan results for $($Ports.Count) ports to logs\samples\portscan.csv"
