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
                 'PesterAssessments', 'PesterCommands', 'UpdateTestServices')]
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
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         Zero Trust Assessment - Test Runner             ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Platform : $($platform.OS) | PowerShell $($platform.PSVersion)" -ForegroundColor DarkGray
    if ($platform.Codespaces) {
        $csName = if ($platform.CodespaceName) { " ($($platform.CodespaceName))" } else { "" }
        Write-Host "  Environment: Codespaces$csName (device code auth auto-enabled)" -ForegroundColor DarkGray
    }
    elseif ($platform.Headless) {
        Write-Host "  Environment: Headless/SSH (device code auth auto-enabled)" -ForegroundColor DarkGray
    }
    if (-not $IsWindows) {
        Write-Host "  Note: SPO/AIP tests require Windows. Some tests may be skipped." -ForegroundColor DarkGray
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
        Step-Status
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

        $grouped = $allTests | Group-Object Pillar | Sort-Object Name
        foreach ($group in $grouped) {
            Write-Host ""
            Write-Host "  $($group.Name) ($($group.Count) tests)" -ForegroundColor Cyan
            Write-Host "  $('-' * 50)" -ForegroundColor DarkGray
            foreach ($test in ($group.Group | Sort-Object TestID)) {
                $svc = if ($test.Service) { "[$(($test.Service) -join ',')]" } else { "" }
                Write-Host ("    {0}  {1}  {2}" -f $test.TestID, $test.Title, $svc) -ForegroundColor Gray
            }
        }
        Write-Host ""
        Write-Host "  Total: $($allTests.Count) tests" -ForegroundColor Green
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

    $invokeParams = @{
        Path = $script:Path
        Days = $script:Days
    }
    if ($script:ShowLog)  { $invokeParams['ShowLog'] = $true }
    if ($Resume)          { $invokeParams['Resume'] = $true }
    if ($RunPillar)       { $invokeParams['Pillar'] = $RunPillar }
    if ($RunTests)        { $invokeParams['Tests'] = $RunTests }

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

function Step-Disconnect {
    Write-MenuHeader "Disconnecting"
    try {
        Disconnect-ZtAssessment -IncludeCleanup
        Write-Host "Disconnected from all services." -ForegroundColor Green
    }
    catch {
        Write-Host "Disconnect issue: $_" -ForegroundColor Yellow
    }
}

# ── Interactive Menu ─────────────────────────────────────────────────────────

function Show-Menu {
    Write-Host "  ── Setup ──" -ForegroundColor DarkCyan
    Write-Host "  [1]  Install / Import module from source" -ForegroundColor White
    Write-Host "  [2]  Connect to tenant" -ForegroundColor White
    Write-Host "  [3]  Check connection status" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Assessment ──" -ForegroundColor DarkCyan
    Write-Host "  [4]  List available tests" -ForegroundColor White
    Write-Host "  [5]  Run FULL assessment (all pillars)" -ForegroundColor White
    Write-Host "  [6]  Run a specific PILLAR (Identity/Devices/Network/Data)" -ForegroundColor White
    Write-Host "  [7]  Run specific TEST(s) by ID" -ForegroundColor White
    Write-Host "  [8]  Resume previous assessment" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Code Tests (offline) ──" -ForegroundColor DarkCyan
    Write-Host "  [9]  Run ALL Pester tests (general + commands + assessments)" -ForegroundColor White
    Write-Host "  [10] Run Pester - General tests only" -ForegroundColor White
    Write-Host "  [11] Run Pester - Command tests only" -ForegroundColor White
    Write-Host "  [12] Run Pester - Assessment tests only" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Maintenance ──" -ForegroundColor DarkCyan
    Write-Host "  [13] Update test Service metadata (Update-ZtTestService)" -ForegroundColor White
    Write-Host "  [D]  Disconnect from tenant" -ForegroundColor White
    Write-Host "  [Q]  Quit" -ForegroundColor White
    Write-Host ""
}

function Invoke-InteractiveMenu {
    Write-Banner

    while ($true) {
        Show-Menu
        $choice = Read-Host "Select an option"

        switch ($choice.Trim().ToUpper()) {
            '1'  { Step-Install }
            '2'  { Step-Connect }
            '3'  { Step-Status }
            '4'  {
                $filterPillar = Read-Host "Filter by pillar? (Identity/Devices/Network/Data or Enter for all)"
                if ($filterPillar -and $filterPillar -in 'Identity', 'Devices', 'Network', 'Data') {
                    $script:Pillar = $filterPillar
                }
                else { $script:Pillar = $null }
                Step-ListTests
            }
            '5'  { Step-RunAssessment }
            '6'  {
                $p = Read-Host "Which pillar? (Identity/Devices/Network/Data)"
                if ($p -in 'Identity', 'Devices', 'Network', 'Data') {
                    Step-RunAssessment -RunPillar $p
                }
                else {
                    Write-Host "Invalid pillar: $p" -ForegroundColor Red
                }
            }
            '7'  {
                $ids = Read-Host "Enter test ID(s), comma-separated (e.g. 21770,21771)"
                $testIds = $ids -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                if ($testIds) {
                    Step-RunAssessment -RunTests $testIds
                }
                else {
                    Write-Host "No test IDs entered." -ForegroundColor Red
                }
            }
            '8'  { Step-RunAssessment -Resume }
            '9'  { Step-Pester -General $true -Commands $true -Assessments $true }
            '10' { Step-Pester -General $true -Commands $false -Assessments $false }
            '11' { Step-Pester -General $false -Commands $true -Assessments $false }
            '12' { Step-Pester -General $false -Commands $false -Assessments $true }
            '13' { Step-UpdateTestServices }
            'D'  { Step-Disconnect }
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
    }
}
else {
    Invoke-InteractiveMenu
}
