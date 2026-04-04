function Get-ZtSharePointTenantSettings {
    <#
    .SYNOPSIS
        Retrieves SharePoint Online tenant settings via PnP.PowerShell.

    .DESCRIPTION
        Common data-collection helper used by SharePoint assessment tests
        (35005, 35006, 35007, 35008). Wraps Get-PnPTenant with standard
        error handling and progress reporting.

    .PARAMETER Activity
        The activity description shown in the progress bar.

    .OUTPUTS
        PSCustomObject with:
        - Tenant : The tenant settings object returned by Get-PnPTenant (or $null on failure).
        - ErrorMessage : The error record if the call failed (or $null on success).

    .EXAMPLE
        $spo = Get-ZtSharePointTenantSettings -Activity 'Checking sensitivity labels'
        if ($spo.ErrorMessage) { # handle error }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Activity
    )

    Write-ZtProgress -Activity $Activity -Status 'Getting SharePoint Tenant Settings'

    $tenant = $null
    $errorMsg = $null

    try {
        $tenant = Get-PnPTenant -ErrorAction Stop
    }
    catch {
        $errorMsg = $_
        Write-PSFMessage "Error querying SharePoint Tenant Settings: $_" -Level Error
    }

    [PSCustomObject]@{
        Tenant       = $tenant
        ErrorMessage = $errorMsg
    }
}
