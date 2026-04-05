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
                 'Status', 'Resume', 'Pester', 'PesterGeneral',
                 'PesterAssessments', 'PesterCommands', 'UpdateTestServices', 'AuditServices',
                 'DeleteResults', 'ListPlanned', 'RunPlanned', 'CheckPermissions', 'ViewReport',
                 'CheckDependencies', 'ListReports')]
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

    [ValidateSet('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')]
    [string[]] $Service = 'All',

    [switch] $ShowLog,

    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
    [string] $PesterOutput = 'Normal'
)

$ErrorActionPreference = 'Stop'
$script:RepoRoot = $PSScriptRoot
$script:ModuleRoot = Join-Path $PSScriptRoot 'src' 'powershell'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-DevInfo {
    # Shows Mode, Platform, Module, Environment, Configuration inside the banner box
    $manifestPath = Join-Path $script:ModuleRoot 'ZeroTrustAssessment.psd1'
    $version = ''
    if (Test-Path $manifestPath) {
        try {
            $data = Import-PowerShellDataFile $manifestPath -ErrorAction Stop
            if ($data.ModuleVersion) { $version = "v$($data.ModuleVersion)" }
        } catch { }
    }

    $boxWidth = 77
    $border = "║"

    # Build info lines
    $os = if ($IsWindows) { "Windows" } elseif ($IsMacOS) { "macOS" } else { "Linux" }

    # Detect environment — delegate to module when loaded, otherwise inline
    $envLine = $null
    $browserNote = $null
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($mod) {
        $headless = & $mod { Test-ZtHeadlessEnvironment }
        if ($headless.IsCodespaces) {
            $csName = if ($env:CODESPACE_NAME) { " ($env:CODESPACE_NAME)" } else { '' }
            $envLine = "Codespaces$csName"
        } elseif ($headless.IsHeadless) { $envLine = "Headless/SSH" }
        if ($headless.CanLaunchBrowser) { $browserNote = 'Browser available' }
    }
    else {
        # Pre-import fallback: basic environment detection without the full module
        $isContainer = ($env:CODESPACES -eq 'true') -or ($env:REMOTE_CONTAINERS -eq 'true') -or
                       ($env:DEVCONTAINER -eq 'true') -or (Test-Path '/.dockerenv')
        if ($env:CODESPACES -eq 'true') {
            $csName = if ($env:CODESPACE_NAME) { " ($env:CODESPACE_NAME)" } else { '' }
            $envLine = "Codespaces$csName"
        } elseif ($isContainer) { $envLine = "Dev Container" }
        elseif (-not $env:DISPLAY -and -not $env:WAYLAND_DISPLAY -and -not $IsWindows) { $envLine = "Headless/SSH" }
        if ($env:BROWSER -and (Test-Path $env:BROWSER -ErrorAction Ignore)) { $browserNote = 'Browser available' }
    }

    $infoLines = @(
        @{ Label = 'Mode'; Value = 'Developer'; Highlight = $true }
        @{ Label = 'Platform'; Value = "$os | PowerShell $($PSVersionTable.PSVersion)" }
    )
    if ($version) {
        $infoLines += @{ Label = 'Module'; Value = "ZeroTrustAssessment $version (source)" }
    }
    if ($envLine) {
        $envDisplay = if ($browserNote) { "$envLine ($browserNote)" } else { $envLine }
        $infoLines += @{ Label = 'Environment'; Value = $envDisplay }
    }

    # Render each line inside the box
    Write-Host "$border$(' ' * $boxWidth)$border" -ForegroundColor Cyan
    foreach ($info in $infoLines) {
        $label = "  $($info.Label)".PadRight(16)
        $text = "${label}: $($info.Value)"
        $pad = $boxWidth - $text.Length
        if ($pad -lt 0) { $pad = 0; $text = $text.Substring(0, $boxWidth) }
        Write-Host $border -ForegroundColor Cyan -NoNewline
        Write-Host "${label}: " -ForegroundColor DarkGray -NoNewline
        if ($info.Highlight) {
            Write-Host $info.Value -ForegroundColor Magenta -NoNewline
        } else {
            Write-Host $info.Value -ForegroundColor DarkGray -NoNewline
        }
        Write-Host "$(' ' * ($boxWidth - $text.Length))$border" -ForegroundColor Cyan
    }
    Write-Host "╚$("═" * $boxWidth)╝" -ForegroundColor Cyan
    Write-Host ""
}

# Track whether the user explicitly provided -Path
$script:IsDefaultPath = -not $PSBoundParameters.ContainsKey('Path')

function Resolve-DevTenantPath {
    # After connection/cache restore, update $script:Path to a tenant-specific
    # subdirectory when using the default path. Delegates to the module's
    # Resolve-ZtTenantReportPath when loaded, otherwise uses Get-MgContext directly.
    if (-not $script:IsDefaultPath) { return }

    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    $resolved = if ($mod) {
        & $mod { param($b) Resolve-ZtTenantReportPath -BasePath $b -IsDefaultPath $true } $script:BasePath
    }
    else {
        try {
            $ctx = Get-MgContext -ErrorAction Ignore
            if ($ctx -and $ctx.TenantId) { Join-Path $script:BasePath $ctx.TenantId } else { $script:BasePath }
        }
        catch { $script:BasePath }
    }

    if ($resolved -ne $script:Path) {
        $script:Path = $resolved
        Write-Host "  📁 Report path: $resolved" -ForegroundColor DarkGray
    }
}

function Get-DevModuleParams {
    # Builds the hashtable used to delegate to Start-ZtAssessment.
    # Single source of truth — called wherever we need @moduleParams.
    $params = @{ Path = $script:Path; Days = $script:Days }
    if ($script:UseDeviceCode) { $params['UseDeviceCode'] = $true }
    if ($script:TenantId)      { $params['TenantId'] = $script:TenantId }
    if ($script:Service -and $script:Service -ne 'All') { $params['Service'] = $script:Service }
    if ($script:ShowLog)       { $params['ShowLog'] = $true }
    $params
}

function Get-DevConfig {
    # Centralized configuration read — used by Write-DevStatus and Step-Configuration.
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    $tokenCache = if ($mod) { & $mod { Get-ZtTokenCacheEnabled } } else { $true }
    $environment = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.Environment' -Fallback 'Global' } catch { 'Global' }
    $clientId = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.ClientId' -Fallback '' } catch { '' }
    $unlicensedAction = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.UnlicensedAction' -Fallback 'Skip' } catch { 'Skip' }
    $exportThrottle = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.ThrottleLimit.Export' -Fallback 5 } catch { 5 }
    $testThrottle = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.ThrottleLimit.Tests' -Fallback 5 } catch { 5 }
    $testTimeout = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Tests.Timeout' -Fallback '1h' } catch { '1h' }
    @{
        TokenCache       = $tokenCache
        Environment      = $environment
        ClientId         = $clientId
        UnlicensedAction = $unlicensedAction
        ExportThrottle   = $exportThrottle
        TestThrottle     = $testThrottle
        TestTimeout      = $testTimeout
    }
}

function Write-DevStatus {
    # Shows Configuration, Services, and Tenant status
    $env:ZT_BANNER_SHOWN = '1'
    $conn = Get-DevConnectionState
    $cfg = Get-DevConfig

    Write-Host "  ── Configuration ──" -ForegroundColor DarkCyan
    if ($script:IsDefaultPath -and $script:Path -ne $script:BasePath) {
        Write-Host "    Base Path   : $($script:BasePath)" -ForegroundColor DarkGray
        Write-Host "    Report Path : $($script:Path)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "    Path        : $($script:Path)$(if ($script:IsDefaultPath) { ' (auto)' } else { ' (custom)' })" -ForegroundColor DarkGray
    }
    Write-Host "    Days        : $($script:Days)" -ForegroundColor DarkGray
    Write-Host "    Service     : $($script:Service -join ', ')" -ForegroundColor DarkGray
    Write-Host "    Login Cache : $(if ($cfg.TokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor DarkGray
    Write-Host "    Environment : $($cfg.Environment)" -ForegroundColor DarkGray
    Write-Host "    DeviceCode  : $(if ($script:UseDeviceCode) { 'Enabled' } else { 'Auto' })" -ForegroundColor DarkGray
    Write-Host "    Unlicensed  : $($cfg.UnlicensedAction)" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  ── Services ──" -ForegroundColor DarkCyan

    # Delegate to the module's shared service classification
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    $services = if ($mod) {
        $devUseDeviceCode = $script:UseDeviceCode
        & $mod { param($dc) Get-ZtServiceClassification -UseDeviceCode:$dc } $devUseDeviceCode
    } else {
        # Fallback when module isn't loaded — use cached service names
        $script:DevAllowedServices | ForEach-Object {
            [PSCustomObject]@{ Name = $_; Available = $true; Reason = $null; ModuleVersion = $null }
        }
    }

    foreach ($svc in $services) {
        $verTag = if ($svc.ModuleVersion) { " (v$($svc.ModuleVersion))" } else { '' }
        if (-not $svc.Available) {
            Write-Host "    ✗ $($svc.Name)$verTag" -NoNewline -ForegroundColor Red
            Write-Host " — $($svc.Reason)" -ForegroundColor DarkGray
        }
        elseif ($svc.Reason) {
            Write-Host "    ⚠ $($svc.Name)$verTag" -NoNewline -ForegroundColor Yellow
            Write-Host " — $($svc.Reason)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "    ✓ $($svc.Name)$verTag" -ForegroundColor Green
        }
    }

    # Show platform notice if any services are unavailable due to non-Windows
    $unavailable = @($services | Where-Object { -not $_.Available })
    if ($unavailable.Count -gt 0 -and -not $IsWindows) {
        Write-Host ""
        Write-Host "    ℹ️  For full test coverage, run from a Windows device." -ForegroundColor DarkYellow
    }
    Write-Host ""

    Write-Host "  ── Tenant ──" -ForegroundColor DarkCyan
    if ($conn.IsConnected) {
        Write-Host "    Account    : $($conn.Account)" -ForegroundColor Magenta
        Write-Host "    Tenant     : $($conn.Tenant)" -ForegroundColor Gray
        if ($conn.CloudEnvironment) {
            $envColor = if ($conn.CloudEnvironment.IsGovernment) { 'Cyan' } elseif ($conn.CloudEnvironment.IsSovereignCloud) { 'Yellow' } else { 'Magenta' }
            Write-Host "    Cloud      : $($conn.CloudEnvironment.DisplayName)" -ForegroundColor $envColor
        }
        if ($conn.Services -and $conn.Services.Count -gt 0) {
            Write-Host "    Connected  : $($conn.Services -join ', ')" -ForegroundColor Gray
        }
        Write-Host "    TokenCache : $(if ($cfg.TokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
        if ($conn.ScopesValid) {
            Write-Host '    Scopes     : All required scopes present' -ForegroundColor Green
        }
        else {
            Write-Host "    Scopes     : $($conn.MissingScopes.Count) missing" -ForegroundColor Red
        }

        $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
        if ($mod) {
            & $mod { Show-ZtLicenseStatus }
            & $mod { Show-ZtPermissionStatus }
        }
    }
    else {
        Write-Host "    Not connected" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Write-MenuHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "── $Title ──" -ForegroundColor DarkCyan
    Write-Host ""
}

# ── Dev-only: Import from source ─────────────────────────────────────────────

function Test-CachedLogin {
    # After module import, check if there's already a valid Graph context in memory.
    # We intentionally do NOT try to connect here — silent Connect-MgGraph can hang
    # in Codespaces. The actual cache restoration happens when the user chooses Login
    # or runs an assessment (via Restore-ZtCachedConnection in the module).
    $conn = Get-DevConnectionState
    if ($conn.IsConnected) {
        Write-Host ""
        $cloudTag = if ($conn.CloudEnvironment) { " [$($conn.CloudEnvironment.DisplayName)]" } else { '' }
        Write-Host "  ✅ Cached login found: $($conn.Account) ($($conn.Tenant))$cloudTag" -ForegroundColor Green
        if ($conn.Services -and $conn.Services.Count -gt 0) {
            Write-Host "     Services: $($conn.Services -join ', ')" -ForegroundColor DarkGray
        }
    }
}

function Write-StartupBanner {
    # Show the box banner before anything else, even before module import.
    # Uses -Open to leave the bottom border off so Write-DevInfo can continue the box.
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($mod) {
        & $mod { Show-ZtBanner -Open }
    }
    else {
        $bannerScript = Join-Path $script:ModuleRoot 'private' 'utility' 'Show-ZtBanner.ps1'
        if (Test-Path $bannerScript) {
            . $bannerScript
            Show-ZtBanner -Open
        }
        else {
            Write-Host "Microsoft Zero Trust Assessment" -ForegroundColor Cyan
            Write-Host
        }
    }
}

function Step-Install {
    Write-Host "  ── Module Import ──" -ForegroundColor DarkCyan
    $manifestPath = Join-Path $script:ModuleRoot 'ZeroTrustAssessment.psd1'
    if (-not (Test-Path $manifestPath)) {
        Write-Host "  ERROR: Module manifest not found at $manifestPath" -ForegroundColor Red
        return
    }

    try {
        $env:ZT_QUIET_INIT = '1'
        Write-Host "  Loading ZeroTrustAssessment from source..." -ForegroundColor DarkGray -NoNewline
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Import-Module $manifestPath -Force -Global -ErrorAction Stop -WarningAction SilentlyContinue 3>$null
        $sw.Stop()
        # Overwrite the loading line with the result
        Write-Host "`r  ✅ Module loaded ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s)                    " -ForegroundColor Green
    }
    catch {
        Write-Host "" # newline after NoNewline
        Write-Host "  Failed to import module from: $manifestPath" -ForegroundColor Red
        Write-Host "    Error: $_" -ForegroundColor Red
        Write-Host "  Attempting dependency initialization..." -ForegroundColor Gray
        $initScript = Join-Path $script:ModuleRoot 'Initialize-Dependencies.ps1'
        try {
            $env:ZT_QUIET_INIT = $null
            & $initScript
            Import-Module $manifestPath -Force -Global -ErrorAction Stop
            Write-Host "  ✅ Module loaded (after dependency init)." -ForegroundColor Green
        }
        catch {
            Write-Host "  Still failed: $_" -ForegroundColor Red
            Write-Host "  Tip: & '$initScript'" -ForegroundColor Yellow
        }
    }
    finally {
        $env:ZT_QUIET_INIT = $null
    }
    Write-Host ""
}

function Ensure-Module {
    $mod = Get-Module ZeroTrustAssessment
    if (-not $mod) {
        Step-Install
        $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    }
    # Refresh service list from module's source of truth (only if not yet populated)
    if ($mod -and -not $script:DevAllowedServices) {
        $script:DevAllowedServices = @(& $mod { $script:AllowedServices })
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
    $skipped = 0
    $ztMod = Get-Module ZeroTrustAssessment
    $classification = & $ztMod { param($dc) Get-ZtServiceClassification -UseDeviceCode:$dc } $script:UseDeviceCode
    $unavailableSvcs = @($classification | Where-Object { -not $_.Available } | ForEach-Object { $_.Name })
    foreach ($group in $grouped) {
        Write-Host ""
        Write-Host "  ── $($group.Name) ($($group.Count) planned) ──" -ForegroundColor Magenta
        foreach ($test in ($group.Group | Sort-Object TestID)) {
            $blockedSvc = if ($test.Service) { $test.Service | Where-Object { $_ -in $unavailableSvcs } } else { $null }
            if ($blockedSvc) {
                $svcReason = ($classification | Where-Object { $_.Name -eq $blockedSvc[0] }).Reason
                Write-Host ("    SKIP  {0}  {1}  ({2})" -f $test.TestID, $test.Title, $svcReason) -ForegroundColor DarkGray
                $skipped++
            }
            else {
                Write-Host ("          {0}  {1}" -f $test.TestID, $test.Title) -ForegroundColor DarkCyan
            }
        }
    }
    $available = $plannedTests.Count - $skipped
    Write-Host ""
    Write-Host "  Planned   : $available" -ForegroundColor DarkCyan
    if ($skipped -gt 0) {
        Write-Host "  Skipped   : $skipped" -ForegroundColor Yellow
    }
    Write-Host "  Total     : $($plannedTests.Count)" -ForegroundColor DarkGray
    Write-Host ""
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

    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($mod) {
        & $mod { Show-ZtPermissionStatus }
    }
    else {
        Write-Host "  Module not loaded. Import ZeroTrustAssessment first." -ForegroundColor Yellow
    }
}

function Step-ViewReport {
    Write-MenuHeader "View Assessment Report"

    $htmlReport = Join-Path $script:Path $script:ZtReportFileName
    $jsonReport = Join-Path $script:Path $script:ZtExportDirName $script:ZtReportJsonFileName

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

    # Delegate to the module's shared report opener
    $ztMod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($ztMod) {
        & $ztMod { param($p) Open-ZtReport -Path $p -ServeHttp } $htmlReport
    }
    else {
        Write-Host "  Open manually: $htmlReport" -ForegroundColor DarkGray
    }
}

# ── Dev-only: Shared dependency helpers ──────────────────────────────────────

function Get-DevModuleSpecs {
    # Returns all required module specifications from the manifest, platform-aware.
    $manifestPath = Join-Path $script:ModuleRoot 'ZeroTrustAssessment.psd1'
    if (-not (Test-Path $manifestPath)) { return @() }

    $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction Stop

    [Microsoft.PowerShell.Commands.ModuleSpecification[]]$specs = $manifest.RequiredModules
    $specs += $manifest.PrivateData.XPlatPowerShellRequiredModules
    if ($IsWindows -and $manifest.PrivateData.WindowsPowerShellRequiredModules) {
        $specs += $manifest.PrivateData.WindowsPowerShellRequiredModules
    }
    $specs
}

function Get-DevModuleVersionIssues {
    # Checks installed modules against manifest specs. Returns objects for any version mismatches.
    param (
        [Microsoft.PowerShell.Commands.ModuleSpecification[]] $Specs
    )

    $issues = @()
    foreach ($spec in $Specs) {
        $installed = Get-Module -Name $spec.Name -ListAvailable -ErrorAction Ignore |
            Where-Object { $_.Guid -eq $spec.Guid } |
            Sort-Object Version -Descending |
            Select-Object -First 1

        if (-not $installed) { continue } # Missing modules handled by Initialize-Dependencies

        $requiredVer = if ($spec.RequiredVersion) { [version]$spec.RequiredVersion } elseif ($spec.Version) { [version]$spec.Version } else { $null }
        if (-not $requiredVer) { continue }

        $specType = if ($spec.RequiredVersion) { 'exact' } else { 'min' }
        $isBad = if ($specType -eq 'exact') { $installed.Version -ne $requiredVer } else { $installed.Version -lt $requiredVer }

        if ($isBad) {
            $issues += [PSCustomObject]@{
                Name      = $spec.Name
                Installed = $installed.Version
                Required  = $requiredVer
                Type      = $specType
            }
        }
    }
    $issues
}

# ── Dev-only: Startup dependency version check ──────────────────────────────

function Step-VerifyDependencyVersions {
    # Quick startup check: are installed dependency versions meeting manifest requirements?
    # Delegates to the module's Resolve-ZtServiceRequiredModule for detection and
    # Update-ZtRequiredModule for fixing, keeping a single source of truth.
    $ztMod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if (-not $ztMod) { return }

    $allServices = & $ztMod { $script:AllowedServices }
    # Only check modules for services that can run on this platform (auth constraints don't affect module install)
    $classification = & $ztMod { Get-ZtServiceClassification }
    $platformServices = @($classification | Where-Object { $_.Available } | ForEach-Object { $_.Name })

    $resolved = & $ztMod { param($svc) Resolve-ZtServiceRequiredModule -Service $svc } $platformServices
    $unavailable = @($resolved.Errors | Where-Object { $_.ErrorMessage -match 'below the required minimum|does not match required version|cannot be found' })
    if ($unavailable.Count -eq 0) { return }

    # Guard against re-triggering after we already tried to fix it this session
    if ($script:_dependencyFixAttempted) {
        Write-Host ""
        Write-Host "  ⚠️  Dependency issues persist after upgrade attempt:" -ForegroundColor Yellow
        foreach ($err in $unavailable) {
            Write-Host "    ❌ $($err.Service): $($err.ErrorMessage)" -ForegroundColor Red
        }
        Write-Host "  Run Update-ZtRequiredModule manually if the issue continues." -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    Write-Host ""
    Write-Host "  ⚠️  Dependency issues detected:" -ForegroundColor Yellow
    foreach ($err in $unavailable) {
        Write-Host "    ❌ $($err.Service): $($err.ErrorMessage)" -ForegroundColor Red
    }
    Write-Host ""

    $answer = Read-Host "  Fix now? (Y/N) [N]"
    if ($answer.Trim().ToUpper() -eq 'Y') {
        $script:_dependencyFixAttempted = $true
        Write-Host ""
        Update-ZtRequiredModule -Confirm:$false
        Write-Host ""
        Write-Host "  Reimporting module..." -ForegroundColor DarkGray
        Step-Install
        Write-Host "  ✅ Done." -ForegroundColor Green
        Write-Host ""
    }
    else {
        Write-Host "  Skipping. Some services may be unavailable." -ForegroundColor DarkGray
        Write-Host ""
    }
}

# ── Dev-only: Dependency upgrades ────────────────────────────────────────────

function Step-CheckDependencyUpgrades {
    Write-MenuHeader "Check Dependency Upgrades"

    Ensure-Module

    $specs = Get-DevModuleSpecs
    if (-not $specs) {
        Write-Host "  No module specs found." -ForegroundColor Yellow
        return
    }

    $findCmd = if (Get-Command Find-PSResource -ErrorAction Ignore) { 'Find-PSResource' }
               elseif (Get-Command Find-Module -ErrorAction Ignore) { 'Find-Module' }
               else { $null }

    if (-not $findCmd) {
        Write-Host "  Neither Find-PSResource nor Find-Module is available." -ForegroundColor Red
        return
    }

    # Get version issues for quick reference
    $issues = @(Get-DevModuleVersionIssues -Specs $specs)
    $issueNames = $issues.Name

    Write-Host "  Checking PSGallery for latest versions..." -ForegroundColor Cyan
    Write-Host ""

    $hasUpgrade = $false
    foreach ($spec in $specs) {
        $requiredVer = if ($spec.RequiredVersion) { [version]$spec.RequiredVersion } elseif ($spec.Version) { [version]$spec.Version } else { $null }
        $specType = if ($spec.RequiredVersion) { 'exact' } else { 'min' }

        # Check installed version
        $installed = Get-Module -FullyQualifiedName $spec -ListAvailable -ErrorAction Ignore | Select-Object -First 1
        $installedVer = if ($installed) { $installed.Version } else { $null }

        # Check latest on PSGallery
        try {
            $latest = if ($findCmd -eq 'Find-PSResource') {
                Find-PSResource -Name $spec.Name -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1
            } else {
                Find-Module -Name $spec.Name -ErrorAction Stop
            }
            $latestVer = $latest.Version
        } catch {
            $latestVer = $null
        }

        # Determine status
        $status = '✅'; $color = 'Green'; $note = ''

        if (-not $installedVer) {
            $status = '❌'; $color = 'Red'; $note = 'not installed'
        }
        elseif ($spec.Name -in $issueNames) {
            $issue = $issues | Where-Object Name -eq $spec.Name | Select-Object -First 1
            $status = '❌'; $color = 'Red'
            $note = if ($issue.Type -eq 'exact') { "installed v$installedVer, requires exact v$($issue.Required)" }
                    else { "installed v$installedVer < required v$($issue.Required)" }
        }

        if ($latestVer -and $installedVer -and $latestVer -gt $installedVer) {
            $hasUpgrade = $true
            if ($note) { $note += ', ' }
            $note += "upgrade available: v$latestVer"
            if ($color -eq 'Green') { $status = '⬆️'; $color = 'Yellow' }
        }

        $verDisplay = if ($installedVer) { "v$installedVer" } else { 'n/a' }
        $line = "  $status $($spec.Name) $verDisplay ($specType v$requiredVer)"
        Write-Host $line -ForegroundColor $color -NoNewline
        if ($note) {
            Write-Host " — $note" -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }
    }

    Write-Host ""
    if ($hasUpgrade) {
        $answer = Read-Host "  Upgrades available. Apply now? (Y/N) [N]"
        if ($answer.Trim().ToUpper() -eq 'Y') {
            Write-Host ""
            Update-ZtRequiredModule -Confirm:$false
            Write-Host ""
            Write-Host "  Reimporting module..." -ForegroundColor DarkGray
            Step-Install
        }
        else {
            Write-Host "  Skipped. Run Update-ZtRequiredModule manually to upgrade." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  All dependencies are up to date." -ForegroundColor Green
    }
}

# ── Interactive Menu ─────────────────────────────────────────────────────────

function Get-DevConnectionState {
    # Delegates to the module's Get-ZtConnectionState when loaded,
    # returns a minimal "not connected" state before module import.
    $ztMod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($ztMod) {
        return (& $ztMod { Get-ZtConnectionState })
    }
    [PSCustomObject]@{ IsConnected = $false; Account = $null; Tenant = $null; CloudEnvironment = $null; Services = @(); ScopesValid = $false; MissingScopes = @() }
}

function Test-DevConnected {
    param([switch] $ShowWarning)
    $conn = Get-DevConnectionState
    if (-not $conn.IsConnected -and $ShowWarning) {
        Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow
    }
    $conn.IsConnected
}

function Read-PostAssessment {
    Write-Host ''
    Write-Host '  Press [Q] to quit or any key to return to the menu...' -ForegroundColor DarkCyan
    try {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq [ConsoleKey]::Q) {
            Write-Host '  Bye!' -ForegroundColor Cyan
            return $true
        }
    }
    catch {
        # Non-interactive — fall through to menu
    }
    return $false
}

function Show-Menu {
    $conn = Get-DevConnectionState
    $dimColor = 'DarkGray'

    # ── Setup ──
    $permColor = if ($conn.IsConnected) { 'White' } else { $dimColor }
    Write-Host ""
    Write-Host "  ── Setup ──" -ForegroundColor DarkCyan
    if ($conn.IsConnected) {
        Write-Host "  [1]  Tenant Logout" -ForegroundColor White
    }
    else {
        Write-Host "  [1]  Tenant Login" -ForegroundColor White
    }
    Write-Host "  [P]  Check user logged in permissions" -ForegroundColor $permColor
    Write-Host ""

    # ── Tests ──
    Write-Host "  ── Tests ──" -ForegroundColor DarkCyan
    Write-Host "  [2]  List available tests" -ForegroundColor $(if ($conn.IsConnected) { 'White' } else { $dimColor })
    Write-Host "  [L]  List planned tests (under construction)" -ForegroundColor $(if ($conn.IsConnected) { 'White' } else { $dimColor })
    Write-Host "  [5]  Run specific TEST(s) by ID" -ForegroundColor $(if ($conn.IsConnected) { 'White' } else { $dimColor })
    Write-Host ""

    # ── Assessment (delegates to module) ──
    $assessColor = if ($conn.IsConnected) { 'White' } else { $dimColor }
    Write-Host "  ── Assessment ──" -ForegroundColor DarkCyan
    Write-Host "  [3]  Run FULL assessment" -ForegroundColor $assessColor
    Write-Host "  [F]  Run FULL assessment (including planned)" -ForegroundColor $assessColor
    Write-Host "  [4]  Run a specific PILLAR" -ForegroundColor $assessColor
    Write-Host "  [R]  Run planned tests only (Preview)" -ForegroundColor $assessColor
    Write-Host "  [6]  Resume previous assessment" -ForegroundColor $assessColor
    Write-Host ""

    # ── Report ──
    $hasReport = Test-Path (Join-Path $script:Path $script:ZtReportFileName)
    $hasResults = Test-Path $script:Path
    $hasAny = $hasReport -or $hasResults
    Write-Host "  ── Report ──" -ForegroundColor DarkCyan
    if ($hasReport) {
        Write-Host "  [V]  View last assessment report" -ForegroundColor White
    }
    else {
        Write-Host "  [V]  View last assessment report (no report found)" -ForegroundColor DarkGray
    }
    Write-Host "  [T]  Browse all tenant reports" -ForegroundColor White
    if ($hasAny) {
        Write-Host "  [9]  Delete all reports and test results" -ForegroundColor White
    }
    else {
        Write-Host "  [9]  Delete all reports and test results (none found)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # ── Dev-only ──
    Write-Host "  ── Developer ──" -ForegroundColor Magenta
    Write-Host "  [7]  Run Pester tests (All/General/Commands/Assessments)" -ForegroundColor White
    Write-Host "  [8]  Update test Service metadata" -ForegroundColor White
    Write-Host "  [A]  Audit test Service metadata (dry run)" -ForegroundColor White
    Write-Host "  [D]  Check dependency upgrades" -ForegroundColor White
    Write-Host "  [S]  Connection status & permissions" -ForegroundColor $(if ($conn.IsConnected) { 'White' } else { $dimColor })
    Write-Host "  [C]  Configuration" -ForegroundColor White

    # ── Docs Site (context-aware) ──
    $docsRunning = Test-DocsServerRunning
    if ($docsRunning) {
        Write-Host "  [W]  Stop docs site" -ForegroundColor White -NoNewline
        Write-Host "  ● running on :3000" -ForegroundColor Green
        Write-Host "  [B]  Rebuild docs site" -ForegroundColor White
    }
    else {
        Write-Host "  [W]  Start docs site (Docusaurus)" -ForegroundColor White
        Write-Host "  [B]  Build docs site" -ForegroundColor White
    }

    Write-Host "  [Q]  Quit" -ForegroundColor White
    Write-Host ""
}

# ── Docs site helpers ────────────────────────────────────────────────────────

function Test-DocsServerRunning {
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.Connect('localhost', 3000)
        $tcp.Close()
        $true
    }
    catch { $false }
}

function Stop-DocsServerProcess {
    # Kill anything listening on port 3000
    $pids = & lsof -ti :3000 2>$null
    if ($pids) {
        $pids -split "`n" | ForEach-Object {
            $p = $_.Trim()
            if ($p) { Stop-Process -Id $p -Force -ErrorAction Ignore }
        }
    }
}

function Ensure-DocsNodeModules {
    param([string]$DocsDir)
    if (-not (Test-Path (Join-Path $DocsDir 'node_modules'))) {
        Write-Host "  Installing dependencies..." -ForegroundColor Gray
        Push-Location $DocsDir
        try { npm install } finally { Pop-Location }
    }
}

function Step-DocsStart {
    Write-MenuHeader "Start Docs Site (Docusaurus)"

    $docsDir = Join-Path $PSScriptRoot 'src' 'react'
    if (-not (Test-Path (Join-Path $docsDir 'package.json'))) {
        Write-Host "  Docs site not found at: $docsDir" -ForegroundColor Red
        return
    }

    if (Test-DocsServerRunning) {
        Write-Host "  Docs server is already running on port 3000." -ForegroundColor Yellow
        return
    }

    Ensure-DocsNodeModules -DocsDir $docsDir

    Write-Host "  Starting Docusaurus dev server on port 3000..." -ForegroundColor Cyan
    Start-Process -FilePath 'bash' -ArgumentList '-c', "cd '$docsDir' && npm run start > /dev/null 2>&1" -NoNewWindow
    # Wait briefly for the server to spin up
    $attempts = 0
    while ($attempts -lt 15 -and -not (Test-DocsServerRunning)) {
        Start-Sleep -Milliseconds 500
        $attempts++
    }
    if (Test-DocsServerRunning) {
        Write-Host "  Docs server running on http://localhost:3000" -ForegroundColor Green
    }
    else {
        Write-Host "  Server starting (may take a moment)... check port 3000" -ForegroundColor Yellow
    }
}

function Step-DocsStop {
    Write-MenuHeader "Stop Docs Site"

    if (-not (Test-DocsServerRunning)) {
        Write-Host "  Docs server is not running." -ForegroundColor Yellow
        return
    }

    Write-Host "  Stopping docs server..." -ForegroundColor Cyan
    Stop-DocsServerProcess
    Start-Sleep -Milliseconds 500
    if (Test-DocsServerRunning) {
        Write-Host "  Server may still be shutting down." -ForegroundColor Yellow
    }
    else {
        Write-Host "  Docs server stopped." -ForegroundColor Green
    }
}

function Step-DocsBuild {
    $wasRunning = Test-DocsServerRunning
    $label = if ($wasRunning) { 'Rebuild' } else { 'Build' }
    Write-MenuHeader "$label Docs Site"

    $docsDir = Join-Path $PSScriptRoot 'src' 'react'
    if (-not (Test-Path (Join-Path $docsDir 'package.json'))) {
        Write-Host "  Docs site not found at: $docsDir" -ForegroundColor Red
        return
    }

    Ensure-DocsNodeModules -DocsDir $docsDir

    if ($wasRunning) {
        Write-Host "  Stopping running server first..." -ForegroundColor Gray
        Stop-DocsServerProcess
        Start-Sleep -Milliseconds 500
    }

    Write-Host "  Building Docusaurus site..." -ForegroundColor Cyan
    Push-Location $docsDir
    try {
        npm run build
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Build complete! Output in: $(Join-Path $docsDir 'build')" -ForegroundColor Green
        }
        else {
            Write-Host "  Build failed (exit code $LASTEXITCODE)." -ForegroundColor Red
            return
        }
    }
    finally { Pop-Location }

    if ($wasRunning) {
        Write-Host "  Restarting dev server..." -ForegroundColor Gray
        Start-Process -FilePath 'bash' -ArgumentList '-c', "cd '$docsDir' && npm run start > /dev/null 2>&1" -NoNewWindow
        $attempts = 0
        while ($attempts -lt 15 -and -not (Test-DocsServerRunning)) {
            Start-Sleep -Milliseconds 500
            $attempts++
        }
        if (Test-DocsServerRunning) {
            Write-Host "  Docs server restarted on http://localhost:3000" -ForegroundColor Green
        }
        else {
            Write-Host "  Server restarting (may take a moment)..." -ForegroundColor Yellow
        }
    }
}

function Step-Configuration {
    while ($true) {
        $cfg = Get-DevConfig
        $tokenCache = $cfg.TokenCache
        $environment = $cfg.Environment
        $clientId = $cfg.ClientId
        $unlicensedAction = $cfg.UnlicensedAction
        $exportThrottle = $cfg.ExportThrottle
        $testThrottle = $cfg.TestThrottle
        $testTimeout = $cfg.TestTimeout

        Write-Host ""
        Write-Host "  ── Configuration ──" -ForegroundColor DarkCyan
        Write-Host ""
        if ($script:IsDefaultPath -and $script:Path -ne $script:BasePath) {
            Write-Host "  [1]  Base Path      : $($script:BasePath)" -ForegroundColor Gray
            Write-Host "       Report Path    : $($script:Path)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  [1]  Path           : $($script:Path)$(if ($script:IsDefaultPath) { ' (auto — resolves per tenant)' } else { '' })" -ForegroundColor Gray
        }
        Write-Host "  [2]  Days           : $($script:Days)" -ForegroundColor Gray
        Write-Host "  [3]  Service        : $($script:Service -join ', ')" -ForegroundColor Gray
        Write-Host "  [4]  Login Cache    : $(if ($tokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
        Write-Host "  [5]  TenantId       : $(if ($script:TenantId) { $script:TenantId } else { '(not set)' })" -ForegroundColor Gray
        Write-Host "  [6]  ShowLog        : $(if ($script:ShowLog) { 'Yes' } else { 'No' })" -ForegroundColor Gray
        Write-Host "  [7]  PesterOutput   : $($script:PesterOutput)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ── Advanced ──" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  [8]  Environment    : $environment" -ForegroundColor Gray
        Write-Host "  [9]  ClientId       : $(if ($clientId) { $clientId } else { '(not set)' })" -ForegroundColor Gray
        Write-Host "  [E]  ExportThrottle : $exportThrottle" -ForegroundColor Gray
        Write-Host "  [T]  TestThrottle   : $testThrottle" -ForegroundColor Gray
        Write-Host "  [O]  TestTimeout    : $testTimeout" -ForegroundColor Gray
        Write-Host "  [U]  UnlicensedAction: $unlicensedAction" -ForegroundColor Gray
        Write-Host "  [X]  DeviceCode     : $(if ($script:UseDeviceCode) { 'Enabled' } else { 'Auto' })" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [B]  Back to main menu" -ForegroundColor White
        Write-Host ""

        $pick = Read-Host "Select setting to change"

        switch ($pick.Trim().ToUpper()) {
            '1' {
                if ($script:IsDefaultPath) {
                    Write-Host "  Current base path: $($script:BasePath)" -ForegroundColor DarkGray
                    Write-Host "  Reports auto-resolve to: {base}/{tenantId}/ per tenant" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "  Explicit path (no auto tenant resolution)" -ForegroundColor DarkGray
                }
                Write-Host "  Enter new base path, 'R' to reset to default, or empty to keep:" -ForegroundColor DarkGray
                $val = Read-Host "  Path [$($script:BasePath)]"
                if ($val.Trim().ToUpper() -eq 'R') {
                    $script:BasePath = $script:ZtDefaultReportPath
                    $script:IsDefaultPath = $true
                    $script:Path = $script:BasePath
                    Resolve-DevTenantPath
                    Write-Host "  → Reset to default: $($script:BasePath) (auto tenant resolution enabled)" -ForegroundColor Green
                }
                elseif ($val) {
                    $script:Path = $val
                    $script:BasePath = $val
                    $script:IsDefaultPath = $false
                    Write-Host "  → Path set to: $val (tenant auto-resolution disabled)" -ForegroundColor Green
                }
            }
            '2' {
                $val = Read-Host "  New Days (1-30) [$($script:Days)]"
                if ($val -match '^\d+$' -and [int]$val -ge 1 -and [int]$val -le 30) {
                    $script:Days = [int]$val; Write-Host "  → Days set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Must be 1-30." -ForegroundColor Red }
            }
            '3' {
                Write-Host "  Available: All, $($script:DevAllowedServices -join ', ')" -ForegroundColor DarkGray
                $val = Read-Host "  Service(s) comma-separated [$($script:Service -join ', ')]"
                if ($val) {
                    $services = $val -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $valid = @('All') + $script:DevAllowedServices
                    $invalid = $services | Where-Object { $_ -notin $valid }
                    if ($invalid) { Write-Host "  Invalid service(s): $($invalid -join ', ')" -ForegroundColor Red }
                    else { $script:Service = $services; Write-Host "  → Service set to: $($services -join ', ')" -ForegroundColor Green }
                }
            }
            '4' {
                $current = if ($tokenCache) { 'Enabled' } else { 'Disabled' }
                $val = Read-Host "  Login Cache - Enable or Disable? (E/D) [$current]"
                switch ($val.Trim().ToUpper()) {
                    'E' { Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.UseTokenCache' -Value $true; Write-Host "  → Login Cache: Enabled" -ForegroundColor Green }
                    'D' { Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.UseTokenCache' -Value $false; Write-Host "  → Login Cache: Disabled" -ForegroundColor Green }
                }
            }
            '5' {
                $val = Read-Host "  TenantId (GUID or empty to clear) [$($script:TenantId)]"
                $script:TenantId = $val
                if ($val) { Write-Host "  → TenantId set to: $val" -ForegroundColor Green }
                else { Write-Host "  → TenantId cleared" -ForegroundColor Green }
            }
            '6' {
                $current = if ($script:ShowLog) { 'Yes' } else { 'No' }
                $val = Read-Host "  Show verbose log? (Y/N) [$current]"
                switch ($val.Trim().ToUpper()) {
                    'Y' { $script:ShowLog = $true; Write-Host "  → ShowLog: Yes" -ForegroundColor Green }
                    'N' { $script:ShowLog = $false; Write-Host "  → ShowLog: No" -ForegroundColor Green }
                }
            }
            '7' {
                Write-Host "  Available: None, Normal, Detailed, Diagnostic" -ForegroundColor DarkGray
                $val = Read-Host "  PesterOutput [$($script:PesterOutput)]"
                if ($val -in 'None', 'Normal', 'Detailed', 'Diagnostic') {
                    $script:PesterOutput = $val; Write-Host "  → PesterOutput set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Use: None, Normal, Detailed, Diagnostic" -ForegroundColor Red }
            }
            '8' {
                Write-Host "  Available: Global, China, Germany, USGov, USGovDoD" -ForegroundColor DarkGray
                $val = Read-Host "  Environment [$environment]"
                if ($val -in 'Global', 'China', 'Germany', 'USGov', 'USGovDoD') {
                    Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.Environment' -Value $val
                    Write-Host "  → Environment set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Use: Global, China, Germany, USGov, USGovDoD" -ForegroundColor Red }
            }
            '9' {
                $val = Read-Host "  ClientId (GUID or empty to clear) [$clientId]"
                Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.ClientId' -Value $val
                if ($val) { Write-Host "  → ClientId set to: $val" -ForegroundColor Green }
                else { Write-Host "  → ClientId cleared" -ForegroundColor Green }
            }
            'E' {
                $val = Read-Host "  Export throttle limit (1-20) [$exportThrottle]"
                if ($val -match '^\d+$' -and [int]$val -ge 1 -and [int]$val -le 20) {
                    Set-PSFConfig -Module ZeroTrustAssessment -Name 'ThrottleLimit.Export' -Value ([int]$val)
                    Write-Host "  → ExportThrottle set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Must be 1-20." -ForegroundColor Red }
            }
            'T' {
                $val = Read-Host "  Test throttle limit (1-20) [$testThrottle]"
                if ($val -match '^\d+$' -and [int]$val -ge 1 -and [int]$val -le 20) {
                    Set-PSFConfig -Module ZeroTrustAssessment -Name 'ThrottleLimit.Tests' -Value ([int]$val)
                    Write-Host "  → TestThrottle set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Must be 1-20." -ForegroundColor Red }
            }
            'O' {
                Write-Host "  Format: e.g. '1h', '30m', '2h'. Use '0' to disable." -ForegroundColor DarkGray
                $val = Read-Host "  TestTimeout [$testTimeout]"
                if ($val) {
                    try {
                        $ts = [timespan]$val
                        Set-PSFConfig -Module ZeroTrustAssessment -Name 'Tests.Timeout' -Value $val
                        Write-Host "  → TestTimeout set to: $val" -ForegroundColor Green
                    }
                    catch { Write-Host "  Invalid timespan format." -ForegroundColor Red }
                }
            }
            'U' {
                Write-Host "  Skip = silently skip unlicensed tests. Warn = show as failed." -ForegroundColor DarkGray
                $val = Read-Host "  UnlicensedAction (Skip/Warn) [$unlicensedAction]"
                if ($val -in 'Skip', 'Warn') {
                    Set-PSFConfig -Module ZeroTrustAssessment -Name 'Tests.UnlicensedAction' -Value $val
                    Write-Host "  → UnlicensedAction set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Use: Skip, Warn" -ForegroundColor Red }
            }
            'X' {
                $current = if ($script:UseDeviceCode) { 'Enabled' } else { 'Auto' }
                Write-Host "  Auto = detect headless environment. Enabled = always use device code." -ForegroundColor DarkGray
                $val = Read-Host "  DeviceCode (A=Auto/E=Enabled) [$current]"
                switch ($val.Trim().ToUpper()) {
                    'A' { $script:UseDeviceCode = $false; Write-Host "  → DeviceCode: Auto" -ForegroundColor Green }
                    'E' { $script:UseDeviceCode = $true; Write-Host "  → DeviceCode: Enabled" -ForegroundColor Green }
                }
            }
            'B' { return }
            default { Write-Host "  Invalid option: $pick" -ForegroundColor Red }
        }
    }
}

function Invoke-InteractiveMenu {
    $firstLoop = $true
    while ($true) {
        if ($firstLoop) {
            # First iteration: startup already displayed banner + dev info — just add status + menu
            Write-DevStatus
            $firstLoop = $false
        }
        else {
            Write-StartupBanner
            Write-DevInfo
            Write-DevStatus
        }
        Show-Menu
        $choice = Read-Host "Select an option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }
        Clear-Host
        # Show our own banner header, suppress Start-ZtAssessment's duplicate
        Write-StartupBanner
        Write-DevInfo
        $env:ZT_BANNER_SHOWN = '1'

        $moduleParams = Get-DevModuleParams

        switch ($choice.Trim().ToUpper()) {
            '1' {
                if (Test-DevConnected) {
                    Ensure-Module
                    Start-ZtAssessment -Action Disconnect
                    # Reset path to base after disconnect so next connect resolves fresh
                    if ($script:IsDefaultPath) { $script:Path = $script:BasePath }
                }
                else {
                    Ensure-Module
                    Step-VerifyDependencyVersions
                    Start-ZtAssessment -Action Connect @moduleParams
                    Resolve-DevTenantPath
                }
            }
            '2' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    Start-ZtAssessment -Action ListTests @moduleParams
                }
            }
            '3' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    Start-ZtAssessment -Action RunAll @moduleParams
                    if (Read-PostAssessment) { return }
                }
            }
            'F' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    Start-ZtAssessment -Action RunAll @moduleParams
                    if (Read-PostAssessment) { return }
                }
            }
            '4' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    $p = Read-Host "Which pillar? (Identity/Devices/Network/Data)"
                    if ($p -in 'Identity', 'Devices', 'Network', 'Data') {
                        Start-ZtAssessment -Action RunPillar -Pillar $p @moduleParams
                        if (Read-PostAssessment) { return }
                    }
                    else { Write-Host "Invalid pillar: $p" -ForegroundColor Red }
                }
            }
            '5' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    $ids = Read-Host "Enter test ID(s), comma-separated"
                    $testIds = $ids -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    if ($testIds) {
                        Start-ZtAssessment -Action RunTests -Tests $testIds @moduleParams
                        if (Read-PostAssessment) { return }
                    }
                    else { Write-Host "No test IDs entered." -ForegroundColor Red }
                }
            }
            '6' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    Start-ZtAssessment -Action Resume @moduleParams
                    if (Read-PostAssessment) { return }
                }
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
            'D' { Step-CheckDependencyUpgrades }
            '9' {
                Ensure-Module
                Start-ZtAssessment -Action DeleteResults @moduleParams
            }
            'V' { Step-ViewReport }
            'T' {
                Ensure-Module
                Start-ZtAssessment -Action ListReports -Path $script:BasePath
            }
            'L' { if (Test-DevConnected -ShowWarning) { Step-ListPlannedTests } }
            'R' {
                if (Test-DevConnected -ShowWarning) { Step-RunPlannedTests }
            }
            'P' {
                if (Test-DevConnected -ShowWarning) { Step-CheckPermissions }
            }
            'S' {
                Ensure-Module
                if (Test-DevConnected -ShowWarning) {
                    Start-ZtAssessment -Action Status @moduleParams
                }
            }
            'C' { Step-Configuration }
            'W' { if (Test-DocsServerRunning) { Step-DocsStop } else { Step-DocsStart } }
            'B' { Step-DocsBuild }
            'Q' { Write-Host "Bye!" -ForegroundColor Cyan; return }
            default { Write-Host "Invalid option: $choice" -ForegroundColor Red }
        }
        # Reset banner flag so next Invoke-ZtAssessment call shows its own banner if needed
        $env:ZT_BANNER_SHOWN = $null
        Write-Host ""
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────

$script:UseDeviceCode = $UseDeviceCode
$script:UseTokenCache = $UseTokenCache
$script:TenantId = $TenantId
$script:Service = $Service
$script:Path = $Path
$script:BasePath = $Path  # Original base path (before tenant resolution) for ListReports
$script:Days = $Days
$script:ShowLog = $ShowLog
$script:Pillar = $Pillar
$script:PesterOutput = $PesterOutput

# Canonical service list — loaded from manifest when available, hardcoded fallback for pre-import.
# Refreshed after module import so everything stays in sync.
$script:DevAllowedServices = @('Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')

# Apply UseTokenCache to PSFConfig so the module picks it up (default: always on)
Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.UseTokenCache' -Value $true

Clear-Host

function Initialize-DevPostImport {
    # Shared post-import initialization: refresh service list, auto-detect device code,
    # verify dependencies, check cached login, and resolve tenant-specific path.
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    if ($mod) {
        $script:DevAllowedServices = @(& $mod { $script:AllowedServices })
        # Pull module constants into dev script scope so post-import code can use them.
        $script:ZtReportFileName     = & $mod { $script:ZtReportFileName }
        $script:ZtReportJsonFileName = & $mod { $script:ZtReportJsonFileName }
        $script:ZtExportDirName      = & $mod { $script:ZtExportDirName }
        $script:ZtDefaultReportPath  = & $mod { $script:ZtDefaultReportPath }
        if (-not $script:UseDeviceCode) {
            if (& $mod { Get-ZtEffectiveDeviceCode }) { $script:UseDeviceCode = $true }
        }
    }
    Step-VerifyDependencyVersions
    Test-CachedLogin
    Resolve-DevTenantPath
}

if ($Action) {
    # Show banner and info first, then import
    Write-StartupBanner
    Write-DevInfo
    Step-Install
    Initialize-DevPostImport

    $moduleParams = Get-DevModuleParams

    Write-DevStatus

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
        'Pester'             { Step-Pester -General $true -Commands $true -Assessments $true }
        'PesterGeneral'      { Step-Pester -General $true -Commands $false -Assessments $false }
        'PesterAssessments'  { Step-Pester -General $false -Commands $false -Assessments $true }
        'PesterCommands'     { Step-Pester -General $false -Commands $true -Assessments $false }
        'UpdateTestServices' { Step-UpdateTestServices }
        'AuditServices'      { Step-UpdateTestServices -AuditOnly }
        'DeleteResults'      { Start-ZtAssessment -Action DeleteResults @moduleParams }
        'ListPlanned'        { if (Test-DevConnected -ShowWarning) { Step-ListPlannedTests } }
        'RunPlanned'         { Step-RunPlannedTests }
        'CheckPermissions'   { Step-CheckPermissions }
        'ViewReport'         { Step-ViewReport }
        'CheckDependencies'  { Step-CheckDependencyUpgrades }
        'ListReports'        { Start-ZtAssessment -Action ListReports -Path $script:BasePath }
    }
}
else {
    Write-StartupBanner
    Write-DevInfo
    Step-Install
    Initialize-DevPostImport
    Invoke-InteractiveMenu
}
