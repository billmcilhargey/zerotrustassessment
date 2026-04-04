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
                 'CheckDependencies')]
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
    $envLine = if ($env:CODESPACES -eq 'true') {
        $csName = if ($env:CODESPACE_NAME) { " ($env:CODESPACE_NAME)" } else { '' }
        "Codespaces$csName"
    } elseif ($env:REMOTE_CONTAINERS -eq 'true') { "Dev Container" }
    elseif (-not $env:DISPLAY -and -not $IsWindows) { "Headless/SSH" }
    else { $null }

    $infoLines = @(
        @{ Label = 'Mode'; Value = 'Developer'; Highlight = $true }
        @{ Label = 'Platform'; Value = "$os | PowerShell $($PSVersionTable.PSVersion)" }
    )
    if ($version) {
        $infoLines += @{ Label = 'Module'; Value = "ZeroTrustAssessment $version (source)" }
    }
    if ($envLine) {
        $infoLines += @{ Label = 'Environment'; Value = $envLine }
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

function Write-DevStatus {
    # Shows Configuration, Services, and Tenant status
    $env:ZT_BANNER_SHOWN = '1'
    $conn = Get-DevConnectionState
    $tokenCache = try { Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true } catch { $true }

    Write-Host "  ── Configuration ──" -ForegroundColor DarkCyan
    Write-Host "    Path        : $($script:Path)" -ForegroundColor DarkGray
    Write-Host "    Days        : $($script:Days)" -ForegroundColor DarkGray
    Write-Host "    Service     : $($script:Service -join ', ')" -ForegroundColor DarkGray
    Write-Host "    Login Cache : $(if ($tokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  ── Services ──" -ForegroundColor DarkCyan

    # Delegate to the module's shared service classification
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    $services = if ($mod) {
        & $mod { Get-ZtServiceClassification }
    } else {
        # Fallback when module isn't loaded — minimal hardcoded list
        @('Graph', 'Azure', 'ExchangeOnline', 'SecurityCompliance', 'AipService', 'SharePoint') |
            ForEach-Object { [PSCustomObject]@{ Name = $_; Available = $true; Reason = $null } }
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
        Write-Host "    $($conn.Account) ($($conn.Tenant))" -ForegroundColor Green
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
        Write-Host "  ✅ Cached login found: $($conn.Account) ($($conn.Tenant))" -ForegroundColor Green
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
    $manifestPath = Join-Path $script:ModuleRoot 'ZeroTrustAssessment.psd1'
    if (-not (Test-Path $manifestPath)) {
        Write-Host "ERROR: Module manifest not found at $manifestPath" -ForegroundColor Red
        return
    }

    try {
        $env:ZT_QUIET_INIT = '1'
        Import-Module $manifestPath -Force -Global -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to import module from: $manifestPath" -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Red
        Write-Host "Attempting dependency initialization..." -ForegroundColor Gray
        $initScript = Join-Path $script:ModuleRoot 'Initialize-Dependencies.ps1'
        try {
            $env:ZT_QUIET_INIT = $null
            & $initScript
            Import-Module $manifestPath -Force -Global -ErrorAction Stop
            Write-Host "Module imported successfully after dependency init." -ForegroundColor Green
        }
        catch {
            Write-Host "Still failed: $_" -ForegroundColor Red
            Write-Host "Tip: & '$initScript'" -ForegroundColor Yellow
        }
    }
    finally {
        $env:ZT_QUIET_INIT = $null
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
    $skipped = 0
    $windowsOnlyServices = @('AipService')
    foreach ($group in $grouped) {
        Write-Host ""
        Write-Host "  ── $($group.Name) ($($group.Count) planned) ──" -ForegroundColor Magenta
        foreach ($test in ($group.Group | Sort-Object TestID)) {
            $wOnly = -not $IsWindows -and $test.Service -and ($test.Service | Where-Object { $_ -in $windowsOnlyServices })
            if ($wOnly) {
                Write-Host ("    SKIP  {0}  {1}  (Windows only)" -f $test.TestID, $test.Title) -ForegroundColor DarkGray
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

    $allServices = @('Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')
    $platformServices = @($allServices | Where-Object {
        $IsWindows -or $_ -ne 'AipService'
    })

    $resolved = & $ztMod { param($svc) Resolve-ZtServiceRequiredModule -Service $svc } $platformServices
    $unavailable = @($resolved.Errors | Where-Object { $_.ErrorMessage -match 'below the required minimum|does not match required version|not found' })
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
        Write-Host "  To update cached modules, run: Update-ZtRequiredModule" -ForegroundColor Yellow
        Write-Host "  Then restart PowerShell and reimport the module." -ForegroundColor DarkGray
    } else {
        Write-Host "  All dependencies are up to date." -ForegroundColor Green
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
    Write-Host "  [2]  List available tests" -ForegroundColor White
    Write-Host "  [L]  List planned tests (under construction)" -ForegroundColor White
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
    $hasReport = Test-Path (Join-Path $script:Path 'ZeroTrustAssessmentReport.html')
    $hasResults = Test-Path $script:Path
    $hasAny = $hasReport -or $hasResults
    Write-Host "  ── Report ──" -ForegroundColor DarkCyan
    if ($hasReport) {
        Write-Host "  [V]  View last assessment report" -ForegroundColor White
    }
    else {
        Write-Host "  [V]  View last assessment report (no report found)" -ForegroundColor DarkGray
    }
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
    Write-Host "  [C]  Configuration" -ForegroundColor White
    Write-Host "  [Q]  Quit" -ForegroundColor White
    Write-Host ""
}

function Step-Configuration {
    while ($true) {
        $tokenCache = Get-PSFConfigValue -FullName 'ZeroTrustAssessment.Connection.UseTokenCache' -Fallback $true

        Write-Host ""
        Write-Host "  ── Configuration ──" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  [1]  Path        : $($script:Path)" -ForegroundColor Gray
        Write-Host "  [2]  Days        : $($script:Days)" -ForegroundColor Gray
        Write-Host "  [3]  Service     : $($script:Service -join ', ')" -ForegroundColor Gray
        Write-Host "  [4]  Login Cache : $(if ($tokenCache) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Gray
        Write-Host "  [5]  TenantId    : $(if ($script:TenantId) { $script:TenantId } else { '(not set)' })" -ForegroundColor Gray
        Write-Host "  [6]  ShowLog     : $(if ($script:ShowLog) { 'Yes' } else { 'No' })" -ForegroundColor Gray
        Write-Host "  [7]  PesterOutput: $($script:PesterOutput)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [B]  Back to main menu" -ForegroundColor White
        Write-Host ""

        $pick = Read-Host "Select setting to change"

        switch ($pick.Trim().ToUpper()) {
            '1' {
                $val = Read-Host "  New Path [$($script:Path)]"
                if ($val) { $script:Path = $val; Write-Host "  → Path set to: $val" -ForegroundColor Green }
            }
            '2' {
                $val = Read-Host "  New Days (1-30) [$($script:Days)]"
                if ($val -match '^\d+$' -and [int]$val -ge 1 -and [int]$val -le 30) {
                    $script:Days = [int]$val; Write-Host "  → Days set to: $val" -ForegroundColor Green
                }
                elseif ($val) { Write-Host "  Invalid. Must be 1-30." -ForegroundColor Red }
            }
            '3' {
                Write-Host "  Available: All, Graph, Azure, ExchangeOnline, SecurityCompliance, AipService, SharePoint" -ForegroundColor DarkGray
                $val = Read-Host "  Service(s) comma-separated [$($script:Service -join ', ')]"
                if ($val) {
                    $services = $val -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $valid = @('All', 'Graph', 'Azure', 'AipService', 'ExchangeOnline', 'SecurityCompliance', 'SharePoint')
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
            'B' { return }
            default { Write-Host "  Invalid option: $pick" -ForegroundColor Red }
        }
    }
}

function Invoke-InteractiveMenu {
    while ($true) {
        Write-StartupBanner
        Write-DevInfo
        Write-DevStatus
        Show-Menu
        $choice = Read-Host "Select an option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }
        Clear-Host
        $env:ZT_BANNER_SHOWN = $null

        # Build params for Start-ZtAssessment delegation
        $moduleParams = @{ Path = $script:Path; Days = $script:Days }
        if ($script:UseDeviceCode) { $moduleParams['UseDeviceCode'] = $true }
        if ($script:TenantId)      { $moduleParams['TenantId'] = $script:TenantId }
        if ($script:Service -and $script:Service -ne 'All') { $moduleParams['Service'] = $script:Service }
        if ($script:ShowLog)       { $moduleParams['ShowLog'] = $true }

        switch ($choice.Trim().ToUpper()) {
            '1' {
                if ((Get-DevConnectionState).IsConnected) {
                    Ensure-Module
                    Start-ZtAssessment -Action Disconnect
                }
                else {
                    Step-Install
                    Start-ZtAssessment -Action Connect @moduleParams
                }
            }
            '2' {
                Ensure-Module
                Start-ZtAssessment -Action ListTests @moduleParams
            }
            '3' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action RunAll @moduleParams
                }
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
            }
            'F' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action RunAll @moduleParams
                }
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
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
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
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
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
            }
            '6' {
                Ensure-Module
                if ((Get-DevConnectionState).IsConnected) {
                    Start-ZtAssessment -Action Resume @moduleParams
                }
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
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
            'L' { Step-ListPlannedTests }
            'R' {
                if ((Get-DevConnectionState).IsConnected) { Step-RunPlannedTests }
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
            }
            'P' {
                if ((Get-DevConnectionState).IsConnected) { Step-CheckPermissions }
                else { Write-Host "Not connected. Use [1] to login first." -ForegroundColor Yellow }
            }
            'C' { Step-Configuration }
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

# Apply UseTokenCache to PSFConfig so the module picks it up (default: always on)
Set-PSFConfig -Module ZeroTrustAssessment -Name 'Connection.UseTokenCache' -Value $true

# Build common params for Start-ZtAssessment delegation
$moduleParams = @{ Path = $Path; Days = $Days }
if ($UseDeviceCode) { $moduleParams['UseDeviceCode'] = $true }
if ($TenantId)      { $moduleParams['TenantId'] = $TenantId }
if ($Service -and $Service -ne 'All') { $moduleParams['Service'] = $Service }
if ($ShowLog)       { $moduleParams['ShowLog'] = $true }

Clear-Host

if ($Action) {
    # Show banner and info first, then import
    Write-StartupBanner
    Write-DevInfo
    Step-Install
    Step-VerifyDependencyVersions
    Test-CachedLogin
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
        'ListPlanned'        { Step-ListPlannedTests }
        'RunPlanned'         { Step-RunPlannedTests }
        'CheckPermissions'   { Step-CheckPermissions }
        'ViewReport'         { Step-ViewReport }
        'CheckDependencies'  { Step-CheckDependencyUpgrades }
    }
}
else {
    Write-StartupBanner
    Write-DevInfo
    Step-Install
    Step-VerifyDependencyVersions
    Test-CachedLogin
    Clear-Host
    Invoke-InteractiveMenu
}
