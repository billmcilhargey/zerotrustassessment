<#
.SYNOPSIS
    Developer test runner for the Zero Trust Assessment module.
    Works on Windows, Linux, macOS, Codespaces, and dev containers.

.DESCRIPTION
    This script provides a menu-driven interface for contributors and developers.
    Production features (connect, assess, status, resume, disconnect) are delegated
    to Start-ZtAssessment from the module. This script adds developer-only features:

    - Import the module from source (not from PSGallery)
    - Run Pester unit/integration tests
    - Audit or update test Service metadata
    - List and run planned (under construction) tests in preview mode
    - Check permissions

    For end-user usage, install the module from PSGallery and run Start-ZtAssessment
    directly — this script is not needed.

.PARAMETER Action
    Skip the interactive menu and run a specific action directly.

.PARAMETER Pillar
    When Action is RunPillar, specifies which pillar to assess.

.PARAMETER Tests
    When Action is RunTests, specifies one or more test IDs to run.

.PARAMETER Path
    Output folder for assessment reports. Default: ./ZeroTrustReport

.PARAMETER Days
    Number of days of sign-in logs to query (1-30). Default: 30

.PARAMETER UseDeviceCode
    Use device code flow for authentication.
    Auto-enabled in Codespaces and when no display is available.

.PARAMETER TenantId
    Target a specific tenant for authentication.

.PARAMETER Service
    Which services to connect. Default: All

.PARAMETER ShowLog
    Show verbose log output during assessment.

.PARAMETER PesterOutput
    Pester output verbosity. Default: Normal

.EXAMPLE
    ./Invoke-ZtDev.ps1
    # Launches interactive developer menu

.EXAMPLE
    ./Invoke-ZtDev.ps1 -Action Pester
    # Run all Pester tests

.EXAMPLE
    ./Invoke-ZtDev.ps1 -Action RunAll -Path "./MyReport" -Days 14
    # Full assessment from source module

.EXAMPLE
    ./Invoke-ZtDev.ps1 -Action AuditServices
    # Show which tests have stale Service metadata

.EXAMPLE
    ./Invoke-ZtDev.ps1 -Action UpdateTestServices
    # Auto-fix stale Service metadata in test attributes
#>

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Connect', 'RunAll', 'RunPillar', 'RunTests', 'ListTests',
                 'Status', 'Resume', 'Disconnect', 'Pester', 'PesterGeneral',
                 'PesterAssessments', 'PesterCommands', 'UpdateTestServices', 'AuditServices',
                 'DeleteResults', 'ListPlanned', 'RunPlanned', 'CheckPermissions', 'ViewReport')]
    [string] $Action,

    [ValidateSet('Identity', 'Devices', 'Network', 'Data', '')]
    [string] $Pillar,

    [string[]] $Tests,

    [string] $Path = "./ZeroTrustReport",

    [ValidateRange(1, 30)]
    [int] $Days = 30,

    [switch] $UseDeviceCode,

    [switch] $UseTokenCache,

    [string] $TenantId,

    [ValidateSet('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePointOnline')]
    [string[]] $Service = 'All',

    [switch] $ShowLog,

    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
    [string] $PesterOutput = 'Normal'
)

$ErrorActionPreference = 'Stop'
$script:RepoRoot = $PSScriptRoot
$script:ModuleRoot = Join-Path $PSScriptRoot 'src' 'powershell'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-DevBanner {
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    $version = if ($mod) { "v$($mod.Version)" } else { '' }

    if ($mod) {
        & $mod { Show-ZtBanner }
    }
    $env:ZT_BANNER_SHOWN = '1'

    # Platform info from the module's shared helper (available after import)
    $envInfo = if ($mod) { & $mod { Test-ZtHeadlessEnvironment } } else { $null }

    Write-Host "  Mode        : Developer" -ForegroundColor Magenta
    $os = if ($IsWindows) { "Windows" } elseif ($IsMacOS) { "macOS" } else { "Linux" }
    Write-Host "  Platform    : $os | PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    if ($version) {
        Write-Host "  Module      : ZeroTrustAssessment $version (source)" -ForegroundColor DarkGray
    }
    if ($envInfo -and $envInfo.IsCodespaces) {
        $csName = if ($env:CODESPACE_NAME) { " ($env:CODESPACE_NAME)" } else { '' }
        Write-Host "  Environment : Codespaces$csName" -ForegroundColor DarkGray
    }
    elseif ($envInfo -and $envInfo.IsHeadless) {
        Write-Host "  Environment : Headless/SSH" -ForegroundColor DarkGray
    }
    if (-not $IsWindows) {
        Write-Host ""
        Write-Host "  ⚠ Some services require Windows (AipService, SharePointOnline)." -ForegroundColor Yellow
        Write-Host "    A few Data pillar tests will be skipped on this platform." -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Write-MenuHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "── $Title ──" -ForegroundColor Yellow
    Write-Host ""
}

# ── Dev-only: Import from source ─────────────────────────────────────────────

function Step-Install {
    Write-MenuHeader "Installing Dependencies & Importing Module (from source)"

    $manifestPath = Join-Path $script:ModuleRoot 'ZeroTrustAssessment.psd1'
    if (-not (Test-Path $manifestPath)) {
        Write-Host "ERROR: Module manifest not found at $manifestPath" -ForegroundColor Red
        return
    }

    Write-Host "Importing module from source: $manifestPath" -ForegroundColor Gray
    try {
        Import-Module $manifestPath -Force -Global -ErrorAction Stop
        Write-Host "Module imported successfully." -ForegroundColor Green
        $mod = Get-Module ZeroTrustAssessment
        Write-Host "  Version : $($mod.Version)" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to import module: $_" -ForegroundColor Red
        Write-Host "Attempting dependency initialization..." -ForegroundColor Gray
        $initScript = Join-Path $script:ModuleRoot 'Initialize-Dependencies.ps1'
        try {
            & $initScript
            Import-Module $manifestPath -Force -Global -ErrorAction Stop
            Write-Host "Module imported successfully after dependency init." -ForegroundColor Green
        }
        catch {
            Write-Host "Still failed: $_" -ForegroundColor Red
            Write-Host "Tip: & '$initScript'" -ForegroundColor Yellow
        }
    }
}

function Ensure-Module {
    if (-not (Get-Module ZeroTrustAssessment)) {
        Step-Install
    }
}

# ── Dev-only: Pester tests ───────────────────────────────────────────────────

function Step-Pester {
    param(
        [bool] $General = $true,
        [bool] $Commands = $true,
        [bool] $Assessments = $true
    )

    $what = @()
    if ($General)     { $what += 'General' }
    if ($Commands)    { $what += 'Commands' }
    if ($Assessments) { $what += 'Assessments' }
    Write-MenuHeader "Running Pester Tests ($($what -join ' + '))"

    $pesterScript = Join-Path $script:RepoRoot 'code-tests' 'pester.ps1'
    if (-not (Test-Path $pesterScript)) {
        Write-Host "Pester runner not found at: $pesterScript" -ForegroundColor Red
        return
    }

    Write-Host "Running: $pesterScript" -ForegroundColor Gray
    Write-Host "  Output: $($script:PesterOutput)" -ForegroundColor Gray
    Write-Host ""
    & $pesterScript -TestGeneral:$General -TestFunctions:$Commands -TestAssessments:$Assessments -Output $script:PesterOutput
}

# ── Dev-only: Service metadata ───────────────────────────────────────────────

function Step-UpdateTestServices {
    param(
        [switch] $AuditOnly
    )

    $mode = if ($AuditOnly) { "Service Metadata Audit" } else { "Update Service Metadata" }
    Write-MenuHeader $mode

    Ensure-Module

    $testsPath = Join-Path $script:ModuleRoot 'tests'
    if (-not (Test-Path $testsPath)) {
        Write-Host "Tests path not found: $testsPath" -ForegroundColor Red
        return
    }

    Write-Host "  Scanning: $testsPath" -ForegroundColor Gray
    Write-Host ""

    $ztMod = Get-Module ZeroTrustAssessment
    $allowedServices = & $ztMod { $script:AllowedServices }
    $audit = @(& $ztMod { Get-ZtTestServiceAudit -TestsPath $args[0] } $testsPath)
    $stale = @($audit | Where-Object IsStale)
    $upToDate = $audit.Count - $stale.Count

    Write-Host "  Total tests scanned : $($audit.Count)" -ForegroundColor Gray
    Write-Host "  Up to date          : $upToDate" -ForegroundColor Green
    Write-Host "  Need update         : $($stale.Count)" -ForegroundColor $(if ($stale.Count -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""

    if ($stale.Count -eq 0) {
        Write-Host "  All test Service metadata is current." -ForegroundColor Green
        return
    }

    Write-Host "  Stale tests:" -ForegroundColor Yellow
    foreach ($t in $stale | Sort-Object TestId) {
        $declStr = if ($t.DeclaredServices) { $t.DeclaredServices -join ',' } else { '(none)' }
        $detStr = $t.DetectedServices -join ','
        Write-Host "    $($t.TestId)  $declStr → $detStr" -ForegroundColor Gray
    }
    Write-Host ""

    $allDetected = $stale | ForEach-Object { $_.DetectedServices } | Sort-Object -Unique
    if ($allDetected) {
        Write-Host "  Services needed across stale tests:" -ForegroundColor DarkCyan
        foreach ($svc in $allowedServices) {
            $count = @($stale | Where-Object { $_.DetectedServices -contains $svc }).Count
            if ($count -gt 0) {
                Write-Host "    $svc : $count tests" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }

    if ($AuditOnly) {
        Write-Host "  Audit complete. Use UpdateTestServices to apply." -ForegroundColor DarkGray
        return
    }

    & $ztMod { $args[0] | Update-ZtTestServiceAttribute } $stale
}

# ── Dev-only: Planned/preview tests ─────────────────────────────────────────

function Step-ListPlannedTests {
    Write-MenuHeader "Planned Tests (Preview)"

    Ensure-Module

    $allTests = Get-ZtTest
    if (-not $allTests) { Write-Host "  No tests found." -ForegroundColor Yellow; return }

    $testsPath = Join-Path $script:ModuleRoot 'tests'
    $plannedTests = @()
    foreach ($test in $allTests) {
        $testFile = Join-Path $testsPath "Test-Assessment.$($test.TestID).ps1"
        if ((Test-Path $testFile) -and (Select-String -Path $testFile -Pattern 'UnderConstruction' -Quiet)) {
            $plannedTests += $test
        }
    }

    if (-not $plannedTests) { Write-Host "  No planned tests found." -ForegroundColor Yellow; return }

    $grouped = $plannedTests | Group-Object Pillar | Sort-Object Name
    foreach ($group in $grouped) {
        Write-Host ""
        Write-Host "  $($group.Name) ($($group.Count) planned)" -ForegroundColor Cyan
        foreach ($test in ($group.Group | Sort-Object TestID)) {
            Write-Host ("    🔜 {0}  {1}" -f $test.TestID, $test.Title) -ForegroundColor DarkCyan
        }
    }
    Write-Host ""
    Write-Host "  Total: $($plannedTests.Count) planned tests" -ForegroundColor Green
}

function Step-RunPlannedTests {
    Write-MenuHeader "Running Planned Tests (Preview)"

    Ensure-Module

    $allTests = Get-ZtTest
    $testsPath = Join-Path $script:ModuleRoot 'tests'
    $plannedIds = @()
    foreach ($test in $allTests) {
        $testFile = Join-Path $testsPath "Test-Assessment.$($test.TestID).ps1"
        if ((Test-Path $testFile) -and (Select-String -Path $testFile -Pattern 'UnderConstruction' -Quiet)) {
            $plannedIds += "$($test.TestID)"
        }
    }

    if (-not $plannedIds) { Write-Host "  No planned tests found." -ForegroundColor Yellow; return }

    Write-Host "  Found $($plannedIds.Count) planned tests (Preview mode)" -ForegroundColor Cyan
    Write-Host ""

    # Delegate to Start-ZtAssessment for the actual run
    $runParams = @{ Action = 'RunTests'; Tests = $plannedIds; Path = $script:Path; Days = $script:Days }
    if ($script:ShowLog) { $runParams['ShowLog'] = $true }
    Start-ZtAssessment @runParams
}

function Step-CheckPermissions {
    Write-MenuHeader "Permission Check"

    Ensure-Module

    try {
        $context = Get-MgContext -ErrorAction Stop
        if (-not $context) {
            Write-Host "  Not connected to Microsoft Graph." -ForegroundColor Yellow
            return
        }

        Write-Host "  Account   : $($context.Account)" -ForegroundColor Gray
        Write-Host "  Tenant    : $($context.TenantId)" -ForegroundColor Gray
        Write-Host "  Auth Type : $($context.AuthType)" -ForegroundColor Gray
        Write-Host ""

        $requiredScopes = Get-ZtGraphScope
        $grantedCount = ($requiredScopes | Where-Object { $context.Scopes -contains $_ }).Count
        Write-Host "  Graph Scopes: $grantedCount / $($requiredScopes.Count) granted" -ForegroundColor Gray
        foreach ($scope in ($requiredScopes | Sort-Object)) {
            if ($context.Scopes -contains $scope) {
                Write-Host "    ✅ $scope" -ForegroundColor Green
            }
            else {
                Write-Host "    ❌ $scope" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "  Cannot determine permissions: $_" -ForegroundColor Yellow
    }
}

function Step-ViewReport {
    Write-MenuHeader "View Assessment Report"

    $htmlReport = Join-Path $script:Path 'ZeroTrustAssessmentReport.html'
    $jsonReport = Join-Path $script:Path 'zt-export' 'ZeroTrustAssessmentReport.json'

    if (-not (Test-Path $htmlReport)) {
        Write-Host "  No report found at: $htmlReport" -ForegroundColor Yellow
        Write-Host "  Run an assessment first (option 3) to generate a report." -ForegroundColor DarkGray
        return
    }

    $reportSize = [math]::Round((Get-Item $htmlReport).Length / 1KB, 1)
    $reportDate = (Get-Item $htmlReport).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "  Report : $htmlReport" -ForegroundColor Gray
    Write-Host "  Size   : $reportSize KB" -ForegroundColor Gray
    Write-Host "  Date   : $reportDate" -ForegroundColor Gray

    if (Test-Path $jsonReport) {
        try {
            $json = Get-Content $jsonReport -Raw | ConvertFrom-Json
            $total = ($json | Measure-Object).Count
            if ($json -and $json[0].PSObject.Properties['Result']) {
                $passed = @($json | Where-Object { $_.Result -eq 'Pass' }).Count
                $failed = @($json | Where-Object { $_.Result -eq 'Fail' }).Count
                $skipped = @($json | Where-Object { $_.Result -eq 'Skip' -or $_.Result -eq 'Skipped' }).Count
                Write-Host "  Tests  : $total total — $passed pass, $failed fail, $skipped skipped" -ForegroundColor Gray
            }
        } catch { }
    }

    Write-Host ''

    # Serve or open the report
    if ($IsWindows) {
        Invoke-Item $htmlReport | Out-Null
    }
    elseif (($env:CODESPACES -eq 'true') -or ($env:REMOTE_CONTAINERS -eq 'true') -or
            (Test-Path '/.dockerenv') -or ($env:DEVCONTAINER -eq 'true')) {
        $reportDir = Split-Path $htmlReport -Parent
        $reportFile = Split-Path $htmlReport -Leaf
        $port = 8080

        # Find an available port (8080-8089)
        for ($p = 8080; $p -le 8089; $p++) {
            $inUse = $false
            try {
                $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
                $listener.Start()
                $listener.Stop()
            } catch { $inUse = $true }
            if (-not $inUse) { $port = $p; break }
        }

        $hasNpx = Get-Command npx -ErrorAction Ignore
        if ($hasNpx) {
            Write-Host "  Starting HTTP server on port $port..." -ForegroundColor Cyan
            $null = Start-Job -ScriptBlock {
                param($dir, $port)
                npx -y http-server $dir -p $port -s -c-1 2>&1 | Out-Null
            } -ArgumentList $reportDir, $port

            Start-Sleep -Milliseconds 1500
            $reportUrl = "http://127.0.0.1:$port/$reportFile"

            Write-Host "  Report URL: " -NoNewline -ForegroundColor White
            Write-Host $reportUrl -ForegroundColor Green
            Write-Host ''

            if ($env:BROWSER) {
                try { & $env:BROWSER $reportUrl } catch { }
            }

            Write-Host "  In Codespaces: check the Ports tab if it doesn't open automatically." -ForegroundColor Yellow
            Write-Host "  The server will stop when the PowerShell session ends." -ForegroundColor DarkGray
        }
        else {
            if ($env:BROWSER) { & $env:BROWSER $htmlReport }
            else { Write-Host "  Open manually: $htmlReport" -ForegroundColor DarkGray }
        }
    }
    elseif ($env:BROWSER) {
        & $env:BROWSER $htmlReport
    }
    elseif (Get-Command xdg-open -ErrorAction Ignore) {
        xdg-open $htmlReport
    }
    elseif ($IsMacOS -and (Get-Command open -ErrorAction Ignore)) {
        open $htmlReport
    }
    else {
        Write-Host "  Open manually: $htmlReport" -ForegroundColor DarkGray
    }
}

# ── Interactive Menu ─────────────────────────────────────────────────────────

function Get-DevConnectionState {
    # Thin wrapper: delegates to the module's Get-ZtConnectionState when loaded,
    # returns a minimal "not connected" state otherwise.
    $ztMod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($ztMod) {
        return (& $ztMod { Get-ZtConnectionState })
    }
    return [PSCustomObject]@{ IsConnected = $false; Account = $null; Tenant = $null; Services = @(); ScopesValid = $false; MissingScopes = @() }
}

function Show-Menu {
    $conn = Get-DevConnectionState

    Write-Host ""
    Write-Host "  Microsoft Zero Trust Assessment — Developer Mode" -ForegroundColor Magenta
    Write-Host "  ────────────────────────────────────────────────" -ForegroundColor DarkGray

    if ($conn.IsConnected) {
        Write-Host "  ✅ $($conn.Account) | tenant: $($conn.Tenant)" -ForegroundColor Green
    }
    else {
        Write-Host "  ○  Not connected" -ForegroundColor DarkGray
    }
    Write-Host ""

    # ── Setup ──
    Write-Host "  ── Setup ──" -ForegroundColor DarkCyan
    Write-Host "  [1]  Install from source & connect" -ForegroundColor White
    Write-Host ""

    if ($conn.IsConnected) {
        # ── Assessment (delegates to module) ──
        Write-Host "  ── Assessment ──" -ForegroundColor DarkCyan
        Write-Host "  [2]  List available tests" -ForegroundColor White
        Write-Host "  [3]  Run FULL assessment" -ForegroundColor White
        Write-Host "  [4]  Run a specific PILLAR" -ForegroundColor White
        Write-Host "  [5]  Run specific TEST(s) by ID" -ForegroundColor White
        Write-Host "  [6]  Resume previous assessment" -ForegroundColor White
        Write-Host ""
    }

    # ── Report ──
    $hasReport = Test-Path (Join-Path $script:Path 'ZeroTrustAssessmentReport.html')
    if ($hasReport) {
        Write-Host "  ── Report ──" -ForegroundColor DarkCyan
        Write-Host "  [V]  View last assessment report" -ForegroundColor White
        Write-Host ""
    }

    # ── Preview ──
    Write-Host "  ── Preview / Planned ──" -ForegroundColor DarkCyan
    Write-Host "  [L]  List planned tests (under construction)" -ForegroundColor White
    if ($conn.IsConnected) {
        Write-Host "  [R]  Run planned tests (Preview)" -ForegroundColor White
    }
    Write-Host ""

    # ── Dev-only ──
    Write-Host "  ── Developer ──" -ForegroundColor Magenta
    Write-Host "  [7]  Run Pester tests (All/General/Commands/Assessments)" -ForegroundColor White
    Write-Host "  [8]  Update test Service metadata" -ForegroundColor White
    Write-Host "  [A]  Audit test Service metadata (dry run)" -ForegroundColor White
    Write-Host "  [9]  Delete test results" -ForegroundColor White
    if ($conn.IsConnected) {
        Write-Host "  [P]  Check permissions" -ForegroundColor White
        Write-Host "  [D]  Disconnect" -ForegroundColor White
    }
    Write-Host "  [Q]  Quit" -ForegroundColor White
    Write-Host ""
}

function Invoke-InteractiveMenu {
    Write-DevBanner

    while ($true) {
        Show-Menu
        $choice = Read-Host "Select an option"

        # Build params for Start-ZtAssessment delegation
        $moduleParams = @{ Path = $script:Path; Days = $script:Days }
        if ($script:UseDeviceCode) { $moduleParams['UseDeviceCode'] = $true }
        if ($script:TenantId)      { $moduleParams['TenantId'] = $script:TenantId }
        if ($script:Service -and $script:Service -ne 'All') { $moduleParams['Service'] = $script:Service }
        if ($script:ShowLog)       { $moduleParams['ShowLog'] = $true }

        switch ($choice.Trim().ToUpper()) {
            '1' {
                Step-Install
                Start-ZtAssessment -Action Connect @moduleParams
            }
            '2' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action ListTests @moduleParams
                }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            '3' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action RunAll @moduleParams
                }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            '4' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    $p = Read-Host "Which pillar? (Identity/Devices/Network/Data)"
                    if ($p -in 'Identity', 'Devices', 'Network', 'Data') {
                        Start-ZtAssessment -Action RunPillar -Pillar $p @moduleParams
                    }
                    else { Write-Host "Invalid pillar: $p" -ForegroundColor Red }
                }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            '5' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    $ids = Read-Host "Enter test ID(s), comma-separated"
                    $testIds = $ids -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    if ($testIds) {
                        Start-ZtAssessment -Action RunTests -Tests $testIds @moduleParams
                    }
                    else { Write-Host "No test IDs entered." -ForegroundColor Red }
                }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            '6' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action Resume @moduleParams
                }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            '7' {
                Ensure-Module
                $pesterChoice = Read-Host "Which tests? (A=All, G=General, C=Commands, S=Assessments) [A]"
                switch ($pesterChoice.Trim().ToUpper()) {
                    'G' { Step-Pester -General $true -Commands $false -Assessments $false }
                    'C' { Step-Pester -General $false -Commands $true -Assessments $false }
                    'S' { Step-Pester -General $false -Commands $false -Assessments $true }
                    default { Step-Pester -General $true -Commands $true -Assessments $true }
                }
            }
            '8' { Ensure-Module; Step-UpdateTestServices }
            'A' { Ensure-Module; Step-UpdateTestServices -AuditOnly }
            '9' {
                Ensure-Module
                Start-ZtAssessment -Action DeleteResults @moduleParams
            }
            'V' { Step-ViewReport }
            'L' { Step-ListPlannedTests }
            'R' {
                if ((Get-DevConnectionState).IsConnected) { Step-RunPlannedTests }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            'P' {
                if ((Get-DevConnectionState).IsConnected) { Step-CheckPermissions }
                else { Write-Host "Not connected. Use [1] first." -ForegroundColor Yellow }
            }
            'D' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action Disconnect
                }
                else { Write-Host "Not connected." -ForegroundColor Yellow }
            }
            'Q' { Write-Host "Bye!" -ForegroundColor Cyan; return }
            default { Write-Host "Invalid option: $choice" -ForegroundColor Red }
        }
        Write-Host ""
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────

$script:UseDeviceCode = $UseDeviceCode
$script:UseTokenCache = $UseTokenCache
$script:TenantId = $TenantId
$script:Service = $Service
$script:Path = $Path
$script:Days = $Days
$script:ShowLog = $ShowLog
$script:Pillar = $Pillar
$script:PesterOutput = $PesterOutput

# Build common params for Start-ZtAssessment delegation
$moduleParams = @{ Path = $Path; Days = $Days }
if ($UseDeviceCode) { $moduleParams['UseDeviceCode'] = $true }
if ($TenantId)      { $moduleParams['TenantId'] = $TenantId }
if ($Service -and $Service -ne 'All') { $moduleParams['Service'] = $Service }
if ($ShowLog)       { $moduleParams['ShowLog'] = $true }

if ($Action) {
    # Always import from source first
    Step-Install
    Write-DevBanner

    switch ($Action) {
        'Install'            { <# already done above #> }
        'Connect'            { Start-ZtAssessment -Action Connect @moduleParams }
        'RunAll'             { Start-ZtAssessment -Action RunAll @moduleParams }
        'RunPillar'  {
            if (-not $Pillar) { Write-Host "ERROR: -Pillar is required with -Action RunPillar" -ForegroundColor Red; exit 1 }
            Start-ZtAssessment -Action RunPillar -Pillar $Pillar @moduleParams
        }
        'RunTests'   {
            if (-not $Tests) { Write-Host "ERROR: -Tests is required with -Action RunTests" -ForegroundColor Red; exit 1 }
            Start-ZtAssessment -Action RunTests -Tests $Tests @moduleParams
        }
        'ListTests'          { Start-ZtAssessment -Action ListTests @moduleParams }
        'Status'             { Start-ZtAssessment -Action Status @moduleParams }
        'Resume'             { Start-ZtAssessment -Action Resume @moduleParams }
        'Disconnect'         { Start-ZtAssessment -Action Disconnect }
        'Pester'             { Step-Pester -General $true -Commands $true -Assessments $true }
        'PesterGeneral'      { Step-Pester -General $true -Commands $false -Assessments $false }
        'PesterAssessments'  { Step-Pester -General $false -Commands $false -Assessments $true }
        'PesterCommands'     { Step-Pester -General $false -Commands $true -Assessments $false }
        'UpdateTestServices' { Step-UpdateTestServices }
        'AuditServices'      { Step-UpdateTestServices -AuditOnly }
        'DeleteResults'      { Start-ZtAssessment -Action DeleteResults @moduleParams }
        'ListPlanned'        { Step-ListPlannedTests }
        'RunPlanned'         { Step-RunPlannedTests }
        'CheckPermissions'   { Step-CheckPermissions }
        'ViewReport'        { Step-ViewReport }
    }
}
else {
    Step-Install
    Invoke-InteractiveMenu
}
