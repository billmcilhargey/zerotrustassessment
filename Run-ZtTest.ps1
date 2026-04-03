<#
.SYNOPSIS
    Interactive test runner for the Zero Trust Assessment module.
    Works on Windows, Linux, macOS, Codespaces, and dev containers.

.DESCRIPTION
    This script provides a menu-driven interface to:
    - Ensure PowerShell 7+ is available (auto-installs in Codespaces/Linux if needed)
    - Install dependencies and import the module from source
    - Connect to your Microsoft 365 tenant (interactive, device code, or certificate auth)
    - Run the full assessment or specific pillars (Identity, Devices, Network, Data)
    - Run individual tests by ID
    - List available tests and check connection status
    - Resume a previous assessment run
    - Run Pester unit/integration tests (offline, no tenant needed)
    - Update test service metadata (Update-ZtTestService.ps1)
    - Disconnect when done

    In Codespaces / dev containers, device code auth is used automatically.

.PARAMETER Action
    Skip the interactive menu and run a specific action directly.
    Valid values: Install, Connect, RunAll, RunPillar, RunTests, ListTests, Status, Resume,
                  Disconnect, Pester, PesterGeneral, PesterAssessments, PesterCommands, UpdateTestServices

.PARAMETER Pillar
    When Action is RunPillar, specifies which pillar to assess.
    Valid values: Identity, Devices, Network, Data

.PARAMETER Tests
    When Action is RunTests, specifies one or more test IDs to run.

.PARAMETER Path
    Output folder for assessment reports. Default: ./ZeroTrustReport

.PARAMETER Days
    Number of days of sign-in logs to query (1-30). Default: 30

.PARAMETER UseDeviceCode
    Use device code flow for authentication (useful in containers/remote sessions).
    Auto-enabled in Codespaces and when no display is available.

.PARAMETER TenantId
    Target a specific tenant for authentication.

.PARAMETER Service
    Which services to connect. Default: All
    Valid values: All, Graph, Azure, AipService, ExchangeOnline, SecurityCompliance, SharePointOnline

.PARAMETER ShowLog
    Show verbose log output during assessment.

.PARAMETER PesterOutput
    Pester output verbosity. Default: Normal
    Valid values: None, Normal, Detailed, Diagnostic

.EXAMPLE
    ./Run-ZtTest.ps1
    # Launches interactive menu

.EXAMPLE
    ./Run-ZtTest.ps1 -Action Connect -UseDeviceCode
    # Connect using device code flow

.EXAMPLE
    ./Run-ZtTest.ps1 -Action RunPillar -Pillar Identity -Days 7 -ShowLog
    # Run only Identity pillar tests with 7 days of logs

.EXAMPLE
    ./Run-ZtTest.ps1 -Action RunTests -Tests 21770,21771
    # Run specific tests by ID

.EXAMPLE
    ./Run-ZtTest.ps1 -Action RunAll -Path "./MyReport" -Days 14
    # Full assessment with custom output path and 14 days of logs

.EXAMPLE
    ./Run-ZtTest.ps1 -Action ListTests -Pillar Identity
    # List all Identity pillar tests

.EXAMPLE
    ./Run-ZtTest.ps1 -Action Pester
    # Run all Pester tests (general + commands + assessments)

.EXAMPLE
    ./Run-ZtTest.ps1 -Action PesterGeneral
    # Run only the general/structural Pester tests

.EXAMPLE
    ./Run-ZtTest.ps1 -Action PesterAssessments -PesterOutput Detailed
    # Run assessment-specific Pester tests with detailed output

.EXAMPLE
    ./Run-ZtTest.ps1 -Action UpdateTestServices
    # Run Update-ZtTestService.ps1 to sync Service metadata in test attributes

.EXAMPLE
    ./Run-ZtTest.ps1 -Action Resume
    # Resume a previous run using cached exported data
#>

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Connect', 'RunAll', 'RunPillar', 'RunTests', 'ListTests',
                 'Status', 'Resume', 'Disconnect', 'Pester', 'PesterGeneral',
                 'PesterAssessments', 'PesterCommands', 'UpdateTestServices', 'DeleteResults')]
    [string] $Action,

    [ValidateSet('Identity', 'Devices', 'Network', 'Data', '')]
    [string] $Pillar,

    [string[]] $Tests,

    [string] $Path = "./ZeroTrustReport",

    [ValidateRange(1, 30)]
    [int] $Days = 30,

    [switch] $UseDeviceCode,

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

# ── Environment Detection ────────────────────────────────────────────────────

function Test-IsCodespaces {
    # Codespaces sets CODESPACES=true; also check for common container indicators
    return ($env:CODESPACES -eq 'true') -or
           ($env:REMOTE_CONTAINERS -eq 'true') -or
           (Test-Path '/.dockerenv') -or
           ($env:DEVCONTAINER -eq 'true')
}

function Test-IsHeadless {
    # No display available (SSH, containers, CI)
    if ($IsLinux -or $IsMacOS) {
        return -not $env:DISPLAY -and -not $env:WAYLAND_DISPLAY
    }
    return $false
}

function Get-EffectiveDeviceCode {
    # Auto-enable device code in headless/container environments
    if ($script:UseDeviceCode) { return $true }
    if (Test-IsCodespaces) {
        Write-Host "  Codespaces/container detected - using device code auth automatically." -ForegroundColor Yellow
        return $true
    }
    if (Test-IsHeadless) {
        Write-Host "  No display detected - using device code auth automatically." -ForegroundColor Yellow
        return $true
    }
    return $false
}

function Get-PlatformInfo {
    $info = [ordered]@{
        OS       = if ($IsWindows) { "Windows" } elseif ($IsMacOS) { "macOS" } else { "Linux" }
        PSVersion = $PSVersionTable.PSVersion.ToString()
        Codespaces = Test-IsCodespaces
        Headless   = Test-IsHeadless
    }
    if ($env:CODESPACE_NAME) { $info['CodespaceName'] = $env:CODESPACE_NAME }
    return [PSCustomObject]$info
}

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Banner {
    $platform = Get-PlatformInfo
    $mod = Get-Module ZeroTrustAssessment -ErrorAction Ignore
    $version = if ($mod) { "v$($mod.Version)" } else { '' }

    # Show the banner — use the module's shared function if loaded, otherwise inline it.
    # Note: Invoke-ZtAssessment also calls Show-ZtBanner internally, so we set an
    # environment variable to suppress the duplicate when the assessment runs.
    if ($mod) {
        & $mod { Show-ZtBanner }
    } else { '' }
    # Suppress the duplicate banner inside Invoke-ZtAssessment
    $env:ZT_BANNER_SHOWN = '1'

    Write-Host "  Platform    : $($platform.OS) | PowerShell $($platform.PSVersion)" -ForegroundColor DarkGray
    if ($version) {
        Write-Host "  Module      : ZeroTrustAssessment $version" -ForegroundColor DarkGray
    }
    if ($platform.Codespaces) {
        $csName = if ($platform.CodespaceName) { " ($($platform.CodespaceName))" } else { '' }
        Write-Host "  Environment : Codespaces$csName (device code auth)" -ForegroundColor DarkGray
    }
    elseif ($platform.Headless) {
        Write-Host "  Environment : Headless/SSH (device code auth)" -ForegroundColor DarkGray
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

function Step-Install {
    Write-MenuHeader "Installing Dependencies & Importing Module"

    # Import from source (not from PSGallery) using cross-platform path joining
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
        Write-Host "  Commands: $($mod.ExportedCommands.Keys -join ', ')" -ForegroundColor Gray
    }
    catch {
        Write-Host "Failed to import module: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Attempting dependency initialization..." -ForegroundColor Gray
        $initScript = Join-Path $script:ModuleRoot 'Initialize-Dependencies.ps1'
        try {
            & $initScript
            Import-Module $manifestPath -Force -Global -ErrorAction Stop
            Write-Host "Module imported successfully after dependency init." -ForegroundColor Green
        }
        catch {
            Write-Host "Still failed: $_" -ForegroundColor Red
            Write-Host ""
            Write-Host "Tip: Run this to initialize manually:" -ForegroundColor Yellow
            Write-Host "  & '$initScript'" -ForegroundColor White
        }
    }
}

function Step-Connect {
    Write-MenuHeader "Connecting to Tenant"

    if (-not (Get-Module ZeroTrustAssessment)) {
        Write-Host "Module not loaded. Running install step first..." -ForegroundColor Yellow
        Step-Install
    }

    $connectParams = @{}
    if (Get-EffectiveDeviceCode)   { $connectParams['UseDeviceCode'] = $true }
    if ($script:TenantId)          { $connectParams['TenantId'] = $script:TenantId }
    if ($script:Service -and $script:Service -ne 'All') { $connectParams['Service'] = $script:Service }

    Write-Host "Connecting with params: $($connectParams | ConvertTo-Json -Compress)" -ForegroundColor Gray
    Write-Host ""

    try {
        Connect-ZtAssessment @connectParams
        Write-Host ""
        Write-Host "Connected successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Connection failed: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Tips:" -ForegroundColor Yellow
        Write-Host "  - Use -UseDeviceCode for remote/container sessions" -ForegroundColor White
        Write-Host "  - Use -TenantId to target a specific tenant" -ForegroundColor White
        Write-Host "  - Ensure you have Global Reader or Global Administrator role" -ForegroundColor White
        if (Test-IsCodespaces) {
            Write-Host "  - In Codespaces, follow the device code URL in your browser" -ForegroundColor White
        }
    }
}

function Step-Status {
    Write-MenuHeader "Connection Status"

    try {
        $context = Get-MgContext
        if ($context) {
            Write-Host "  Auth Type : $($context.AuthType)" -ForegroundColor Gray
            Write-Host "  Account   : $($context.Account)" -ForegroundColor Gray
            Write-Host "  Tenant    : $($context.TenantId)" -ForegroundColor Gray
            Write-Host "  Scopes    : $($context.Scopes.Count) granted" -ForegroundColor Gray

            $requiredScopes = Get-ZtGraphScope
            $missing = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }
            if ($missing) {
                Write-Host "  Missing   : $($missing -join ', ')" -ForegroundColor Red
            }
            else {
                Write-Host "  Scopes    : All required scopes present" -ForegroundColor Green
            }
        }
        else {
            Write-Host "  Not connected to Microsoft Graph." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Cannot determine status (Graph module may not be loaded): $_" -ForegroundColor Yellow
    }
}

function Step-ListTests {
    Write-MenuHeader "Available Tests"

    if (-not (Get-Module ZeroTrustAssessment)) {
        Write-Host "Module not loaded. Running install step first..." -ForegroundColor Yellow
        Step-Install
    }

    $listParams = @{}
    if ($script:Pillar) { $listParams['Pillar'] = $script:Pillar }

    try {
        $allTests = Get-ZtTest @listParams
        if (-not $allTests) {
            Write-Host "No tests found." -ForegroundColor Yellow
            return
        }

        $windowsOnlyServices = @('AipService', 'SharePointOnline')
        $isNonWindows = -not $IsWindows
        $skippedCount = 0

        $grouped = $allTests | Group-Object Pillar | Sort-Object Name
        foreach ($group in $grouped) {
            Write-Host ""
            Write-Host "  $($group.Name) ($($group.Count) tests)" -ForegroundColor Cyan
            Write-Host "  $('-' * 50)" -ForegroundColor DarkGray
            foreach ($test in ($group.Group | Sort-Object TestID)) {
                $svc = if ($test.Service) { "[$(($test.Service) -join ',')]" } else { "" }
                $needsWindows = $isNonWindows -and $test.Service -and ($test.Service | Where-Object { $_ -in $windowsOnlyServices })
                if ($needsWindows) {
                    Write-Host ("    {0}  {1}  {2}  (Windows only)" -f $test.TestID, $test.Title, $svc) -ForegroundColor DarkGray
                    $skippedCount++
                }
                else {
                    Write-Host ("    {0}  {1}  {2}" -f $test.TestID, $test.Title, $svc) -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
        $availableCount = $allTests.Count - $skippedCount
        if ($skippedCount -gt 0) {
            Write-Host "  Total: $availableCount / $($allTests.Count) tests available ($skippedCount require Windows)" -ForegroundColor Green
        }
        else {
            Write-Host "  Total: $($allTests.Count) / $($allTests.Count) tests available" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to list tests: $_" -ForegroundColor Red
    }
}

function Step-RunAssessment {
    param(
        [string] $RunPillar,
        [string[]] $RunTests,
        [switch] $Resume
    )

    if (-not (Get-Module ZeroTrustAssessment)) {
        Write-Host "Module not loaded. Running install step first..." -ForegroundColor Yellow
        Step-Install
    }

    # Auto-connect if not already connected
    if (-not (Get-ConnectionState).IsConnected) {
        Write-Host "Not connected. Connecting automatically..." -ForegroundColor Yellow
        Step-Connect
        if (-not (Get-ConnectionState).IsConnected) {
            Write-Host "Connection failed. Cannot run assessment." -ForegroundColor Red
            return
        }
    }

    # If previous results exist (and not resuming), offer to delete first
    if (-not $Resume -and (Test-Path $script:Path)) {
        Write-Host "  Previous results found at: $script:Path" -ForegroundColor Yellow
        if (-not (Confirm-DeleteReportFolder -ReportPath $script:Path)) {
            Write-Host "  Assessment cancelled." -ForegroundColor DarkGray
            return
        }
        Write-Host ""
    }

    $invokeParams = @{
        Path = $script:Path
        Days = $script:Days
    }
    if ($script:ShowLog)  { $invokeParams['ShowLog'] = $true }
    if ($Resume)          { $invokeParams['Resume'] = $true }
    if ($RunPillar)       { $invokeParams['Pillar'] = $RunPillar }
    if ($RunTests)        { $invokeParams['Tests'] = $RunTests }

    # Guard: if Resume requested, check that a previous export actually exists
    if ($Resume) {
        $exportPath = Join-Path $invokeParams.Path 'zt-export'
        $configPath = Join-Path $exportPath 'ztConfig.json'
        if (-not (Test-Path $configPath)) {
            Write-MenuHeader "Resume"
            Write-Host "  No previous assessment found in: $($invokeParams.Path)" -ForegroundColor Yellow
            Write-Host "  Run a full assessment first with [3]." -ForegroundColor Yellow
            return
        }
    }

    $description = if ($Resume) { "Resuming previous assessment" }
                   elseif ($RunTests) { "Running tests: $($RunTests -join ', ')" }
                   elseif ($RunPillar) { "Running $RunPillar pillar" }
                   else { "Running full assessment" }

    Write-MenuHeader $description
    Write-Host "  Output    : $($invokeParams.Path)" -ForegroundColor Gray
    Write-Host "  Days      : $($invokeParams.Days)" -ForegroundColor Gray
    if ($RunPillar) { Write-Host "  Pillar    : $RunPillar" -ForegroundColor Gray }
    if ($RunTests)  { Write-Host "  Tests     : $($RunTests -join ', ')" -ForegroundColor Gray }
    Write-Host ""

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-ZtAssessment @invokeParams
        $sw.Stop()
        Write-Host ""
        Write-Host "Assessment completed in $([math]::Round($sw.Elapsed.TotalMinutes, 1)) minutes." -ForegroundColor Green
        Write-Host "Report: $((Resolve-Path $invokeParams.Path -ErrorAction SilentlyContinue) ?? $invokeParams.Path)" -ForegroundColor Green
    }
    catch {
        $sw.Stop()
        Write-Host "Assessment failed after $([math]::Round($sw.Elapsed.TotalMinutes, 1)) minutes: $_" -ForegroundColor Red
    }
}

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

function Step-UpdateTestServices {
    Write-MenuHeader "Updating Test Service Metadata"

    $updateScript = Join-Path $script:RepoRoot 'Update-ZtTestService.ps1'
    if (-not (Test-Path $updateScript)) {
        Write-Host "Update-ZtTestService.ps1 not found at: $updateScript" -ForegroundColor Red
        return
    }

    $testsPath = Join-Path $script:ModuleRoot 'tests'
    Write-Host "Scanning tests in: $testsPath" -ForegroundColor Gray
    Write-Host "This auto-detects which services (Graph, Azure, ExchangeOnline, etc.)" -ForegroundColor Gray
    Write-Host "each test uses and updates the [ZtTest(Service = ...)] attribute." -ForegroundColor Gray
    Write-Host ""

    & $updateScript -TestsPath $testsPath -Verbose
}

# Returns $true if folder was deleted or doesn't exist, $false if user cancelled.
function Confirm-DeleteReportFolder {
    param([string] $ReportPath)

    if (-not (Test-Path $ReportPath)) { return $true }

    $items = Get-ChildItem -Path $ReportPath -Recurse -ErrorAction SilentlyContinue
    $fileCount = ($items | Where-Object { -not $_.PSIsContainer }).Count
    $folderCount = ($items | Where-Object { $_.PSIsContainer }).Count
    $sizeMB = [math]::Round(($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum / 1MB, 1)

    Write-Host "  Path    : $ReportPath" -ForegroundColor Gray
    Write-Host "  Files   : $fileCount" -ForegroundColor Gray
    Write-Host "  Folders : $folderCount" -ForegroundColor Gray
    Write-Host "  Size    : $sizeMB MB" -ForegroundColor Gray
    Write-Host ""

    $confirm = Read-Host "  Delete all contents? (Y/N) [N]"
    if ($confirm.Trim().ToUpper() -eq 'Y') {
        try {
            Remove-Item -Path $ReportPath -Recurse -Force
            Write-Host "  Deleted: $ReportPath" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "  Failed to delete: $_" -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return $false
    }
}

function Step-DeleteTestResults {
    Write-MenuHeader "Delete Test Results"

    if (-not (Test-Path $script:Path)) {
        Write-Host "  No report folder found at: $script:Path" -ForegroundColor Yellow
        return
    }

    $null = Confirm-DeleteReportFolder -ReportPath $script:Path
}

function Step-Disconnect {
    Write-MenuHeader "Disconnecting"
    try {
        $null = Disconnect-ZtAssessment -IncludeCleanup
        Write-Host "Disconnected from all services." -ForegroundColor Green
    }
    catch {
        Write-Host "Disconnect issue: $_" -ForegroundColor Yellow
    }
}

# ── Interactive Menu ─────────────────────────────────────────────────────────

function Get-ConnectionState {
    # Returns a hashtable with connection info for menu display
    $state = @{ IsConnected = $false; Account = $null; Tenant = $null; Services = @() }
    try {
        if (Get-Module ZeroTrustAssessment) {
            $context = Get-MgContext -ErrorAction Ignore
            if ($null -ne $context) {
                $state.IsConnected = $true
                $state.Account = $context.Account
                $state.Tenant = $context.TenantId
            }
        }
    }
    catch { }
    return $state
}

function Show-Menu {
    $conn = Get-ConnectionState

    # ── Compact header ──
    Write-Host ""
    Write-Host "  Microsoft Zero Trust Assessment" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────" -ForegroundColor DarkGray

    # ── Connection status bar ──
    if ($conn.IsConnected) {
        Write-Host "  ✅ $($conn.Account) | tenant: $($conn.Tenant)" -ForegroundColor Green
    }
    else {
        Write-Host "  ○  Not connected" -ForegroundColor DarkGray
    }
    Write-Host ""

    if (-not $conn.IsConnected) {
        # ── Setup ──
        Write-Host "  ── Setup ──" -ForegroundColor DarkCyan
        Write-Host "  [1]  Connect to tenant (install, connect, show status)" -ForegroundColor White
        Write-Host ""

        # ── Code Tests (offline) ──
        Write-Host "  ── Code Tests (offline) ──" -ForegroundColor DarkCyan
        Write-Host "  [7]  Run Pester tests (All/General/Commands/Assessments)" -ForegroundColor White
        Write-Host ""

        # ── Maintenance ──
        Write-Host "  ── Maintenance ──" -ForegroundColor DarkCyan
        Write-Host "  [8]  Update test Service metadata (Update-ZtTestService)" -ForegroundColor White
        Write-Host "  [9]  Delete test results (clean report folder)" -ForegroundColor White
    }
    else {
        # ── Assessment ──
        Write-Host "  ── Assessment ──" -ForegroundColor DarkCyan
        Write-Host "  [2]  List available tests" -ForegroundColor White
        Write-Host "  [3]  Run FULL assessment (all pillars)" -ForegroundColor White
        Write-Host "  [4]  Run a specific PILLAR (Identity/Devices/Network/Data)" -ForegroundColor White
        Write-Host "  [5]  Run specific TEST(s) by ID" -ForegroundColor White
        Write-Host "  [6]  Resume previous assessment" -ForegroundColor White
        Write-Host ""

        # ── Maintenance ──
        Write-Host "  ── Maintenance ──" -ForegroundColor DarkCyan
        Write-Host "  [P]  Check permissions" -ForegroundColor White
        Write-Host "  [9]  Delete test results (clean report folder)" -ForegroundColor White
        Write-Host "  [D]  Disconnect from tenant" -ForegroundColor White
    }
    Write-Host "  [Q]  Quit" -ForegroundColor White
    Write-Host ""
}

function Step-CheckPermissions {
    Write-MenuHeader "Permission Check"

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
        $missing = $requiredScopes | Where-Object { $context.Scopes -notcontains $_ }

        Write-Host "  Graph Scopes: $grantedCount / $($requiredScopes.Count) granted" -ForegroundColor Gray
        foreach ($scope in ($requiredScopes | Sort-Object)) {
            if ($context.Scopes -contains $scope) {
                Write-Host "    ✅ $scope" -ForegroundColor Green
            }
            else {
                Write-Host "    ❌ $scope" -ForegroundColor Red
            }
        }

        if ($missing) {
            Write-Host ""
            Write-Host "  Reconnect with [R] to request missing scopes." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Cannot determine permissions: $_" -ForegroundColor Yellow
    }
}

function Invoke-InteractiveMenu {
    Write-Banner

    $firstRun = $true
    while ($true) {
        if ($firstRun) {
            $firstRun = $false
        }
        else {
            # On subsequent iterations the previous action output is already visible
            # above, so just draw the menu below it without clearing.
        }
        Show-Menu
        $choice = Read-Host "Select an option"

        switch ($choice.Trim().ToUpper()) {
            '1'  { Step-Install; Step-Connect; Step-Status }
            '2'  {
                if ((Get-ConnectionState).IsConnected) {
                    $script:Pillar = $null
                    Step-ListTests
                }
                else {
                    Write-Host "Not connected. Use [1] to connect first." -ForegroundColor Yellow
                }
            }
            '3'  {
                if ((Get-ConnectionState).IsConnected) {
                    Step-RunAssessment
                }
                else {
                    Write-Host "Not connected. Use [1] to connect first." -ForegroundColor Yellow
                }
            }
            '4'  {
                if ((Get-ConnectionState).IsConnected) {
                    $p = Read-Host "Which pillar? (Identity/Devices/Network/Data)"
                    if ($p -in 'Identity', 'Devices', 'Network', 'Data') {
                        Step-RunAssessment -RunPillar $p
                    }
                    else {
                        Write-Host "Invalid pillar: $p" -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Not connected. Use [1] to connect first." -ForegroundColor Yellow
                }
            }
            '5'  {
                if ((Get-ConnectionState).IsConnected) {
                    $ids = Read-Host "Enter test ID(s), comma-separated (e.g. 21770,21771)"
                    $testIds = $ids -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    if ($testIds) {
                        Step-RunAssessment -RunTests $testIds
                    }
                    else {
                        Write-Host "No test IDs entered." -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Not connected. Use [1] to connect first." -ForegroundColor Yellow
                }
            }
            '6'  {
                if ((Get-ConnectionState).IsConnected) {
                    Step-RunAssessment -Resume
                }
                else {
                    Write-Host "Not connected. Use [1] to connect first." -ForegroundColor Yellow
                }
            }
            '7'  {
                $pesterChoice = Read-Host "Which tests? (A=All, G=General, C=Commands, S=Assessments) [A]"
                switch ($pesterChoice.Trim().ToUpper()) {
                    'G' { Step-Pester -General $true -Commands $false -Assessments $false }
                    'C' { Step-Pester -General $false -Commands $true -Assessments $false }
                    'S' { Step-Pester -General $false -Commands $false -Assessments $true }
                    default { Step-Pester -General $true -Commands $true -Assessments $true }
                }
            }
            '8'  { Step-UpdateTestServices }
            '9'  { Step-DeleteTestResults }
            'P'  {
                if ((Get-ConnectionState).IsConnected) {
                    Step-CheckPermissions
                }
                else {
                    Write-Host "Not connected. Use [1] to connect first." -ForegroundColor Yellow
                }
            }
            'D'  {
                if ((Get-ConnectionState).IsConnected) {
                    Step-Disconnect
                }
                else {
                    Write-Host "Not connected." -ForegroundColor Yellow
                }
            }
            'Q'  {
                Write-Host "Bye!" -ForegroundColor Cyan
                return
            }
            default {
                Write-Host "Invalid option: $choice" -ForegroundColor Red
            }
        }

        Write-Host ""
    }
}

# ── Direct Action Mode ───────────────────────────────────────────────────────

# Persist params at script scope for helper function access
$script:UseDeviceCode = $UseDeviceCode
$script:TenantId = $TenantId
$script:Service = $Service
$script:Path = $Path
$script:Days = $Days
$script:ShowLog = $ShowLog
$script:Pillar = $Pillar
$script:PesterOutput = $PesterOutput

if ($Action) {
    Write-Banner
    switch ($Action) {
        'Install'            { Step-Install }
        'Connect'            { Step-Install; Step-Connect }
        'RunAll'             { Step-RunAssessment }
        'RunPillar'  {
            if (-not $Pillar) {
                Write-Host "ERROR: -Pillar is required with -Action RunPillar" -ForegroundColor Red
                exit 1
            }
            Step-RunAssessment -RunPillar $Pillar
        }
        'RunTests'   {
            if (-not $Tests) {
                Write-Host "ERROR: -Tests is required with -Action RunTests" -ForegroundColor Red
                exit 1
            }
            Step-RunAssessment -RunTests $Tests
        }
        'ListTests'          { Step-Install; Step-ListTests }
        'Status'             { Step-Status }
        'Resume'             { Step-RunAssessment -Resume }
        'Disconnect'         { Step-Disconnect }
        'Pester'             { Step-Pester -General $true -Commands $true -Assessments $true }
        'PesterGeneral'      { Step-Pester -General $true -Commands $false -Assessments $false }
        'PesterAssessments'  { Step-Pester -General $false -Commands $false -Assessments $true }
        'PesterCommands'     { Step-Pester -General $false -Commands $true -Assessments $false }
        'UpdateTestServices' { Step-UpdateTestServices }
        'DeleteResults'      { Step-DeleteTestResults }
    }
}
else {
    Invoke-InteractiveMenu
}
