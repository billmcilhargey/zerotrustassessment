<#
.SYNOPSIS
    Updates the Service attribute in [ZtTest()] for all test files with stale metadata.

.DESCRIPTION
    Imports the ZeroTrustAssessment module and uses Get-ZtTestServiceAudit and
    Update-ZtTestServiceAttribute to detect and fix service metadata in test files.

    Supports -WhatIf / -Confirm via ShouldProcess.

.PARAMETER TestsPath
    Path to the tests directory to scan. Defaults to src/powershell/tests.

.EXAMPLE
    ./build/commands/Update-ZtTestService.ps1
    ./build/commands/Update-ZtTestService.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TestsPath = (Join-Path $PSScriptRoot '..' '..' 'src' 'powershell' 'tests')
)

# Import the module so we get the internal functions
$repoRoot = Join-Path $PSScriptRoot '..' '..'
$modulePath = Join-Path $repoRoot 'src' 'powershell' 'ZeroTrustAssessment.psd1'
Import-Module $modulePath -Force

$ztModule = Get-Module ZeroTrustAssessment

$audit = & $ztModule { Get-ZtTestServiceAudit -TestsPath $args[0] } $TestsPath
$stale = @($audit | Where-Object IsStale)

if ($stale.Count -eq 0) {
    Write-Host "All test Service metadata is current. Nothing to update." -ForegroundColor Green
    return
}

Write-Host "Found $($stale.Count) stale test(s). Updating..." -ForegroundColor Yellow
& $ztModule { $input | Update-ZtTestServiceAttribute } -InputObject $stale
