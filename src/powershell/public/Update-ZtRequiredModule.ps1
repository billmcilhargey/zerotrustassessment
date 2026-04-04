function Update-ZtRequiredModule {
    <#
    .SYNOPSIS
    Force update all required modules used by Zero Trust Assessment to the versions declared in the module manifest.

    .DESCRIPTION
    This cmdlet removes the cached required modules and re-downloads them from PSGallery to ensure the correct
    versions are installed. This is useful when a version mismatch is detected during Connect-ZtAssessment.

    After running this command, you must restart your PowerShell session and reimport the ZeroTrustAssessment module.

    .EXAMPLE
    Update-ZtRequiredModule

    # Clears cached modules and re-downloads the correct versions. Restart PowerShell after running this.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param ()

    $ZTAModulesFolder = Get-ZtModuleCachePath

    if (-not $PSCmdlet.ShouldProcess($ZTAModulesFolder, 'Remove and re-download required modules')) {
        return
    }

    # Step 1: Clear existing cached modules
    Write-Host -Object '🗑️ Removing cached required modules...' -ForegroundColor Cyan
    if (Test-Path -Path $ZTAModulesFolder) {
        Remove-Item -Path $ZTAModulesFolder -Recurse -Force -ErrorAction Continue
        Write-Host -Object ('    ✅ Removed {0}' -f $ZTAModulesFolder) -ForegroundColor Green
    }
    else {
        Write-Host -Object ('    ℹ️ Cache folder not found: {0}' -f $ZTAModulesFolder) -ForegroundColor DarkGray
    }

    # Step 2: Re-run Initialize-Dependencies to re-download the correct versions
    Write-Host -Object '⬇️ Downloading required modules...' -ForegroundColor Cyan
    $ztModule = Get-ZtModule
    $initScript = Join-Path -Path $ztModule.ModuleBase -ChildPath 'Initialize-Dependencies.ps1'
    if (Test-Path -Path $initScript) {
        & $initScript
    }
    else {
        Write-Error -Message 'Could not find Initialize-Dependencies.ps1. Please reimport the ZeroTrustAssessment module.'
        return
    }

    Write-Host
    Write-Host -Object '✅ Required modules updated. Please restart your PowerShell session and reimport ZeroTrustAssessment.' -ForegroundColor Green
}
