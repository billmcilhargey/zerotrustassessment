<#
.SYNOPSIS
    Get license information for a Microsoft 365 product

.DESCRIPTION
    This function retrieves the license information for a Microsoft 365 product from the current tenant.

.PARAMETER Product
    The Microsoft 365 product for which to retrieve the license information.

.EXAMPLE
    Get-ZtLicenseInformation -Product EntraID
#>
function Get-ZtLicenseInformation {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, Mandatory)]
        [ValidateSet('EntraID', 'EntraWorkloadID', 'Intune')]
        [string] $Product
    )

    process {
        $skus = Get-ZtActiveServicePlanId
        $sp = $script:ZtServicePlanIds

        switch ($Product) {
            'EntraID' {
                Write-PSFMessage 'Retrieving license information for Entra ID' -Level Debug -Tag License
                if ($sp.EntraIDGovernance -in $skus) { return 'Governance' }
                if ($sp.EntraIDP2 -in $skus)         { return 'P2' }
                if ($sp.EntraIDP1 -in $skus)         { return 'P1' }
                return 'Free'
            }
            'EntraWorkloadID' {
                Write-PSFMessage 'Retrieving license information for Workload ID' -Level Debug -Tag License
                if ($sp.WorkloadIDP1 -in $skus) { return 'P1' }
                if ($sp.WorkloadIDP2 -in $skus) { return 'P2' }
                return $null
            }
            'Intune' {
                Write-PSFMessage 'Retrieving license information for Intune' -Level Debug -Tag License
                if ($sp.IntuneP1 -in $skus -or $sp.IntuneP1Education -in $skus) { return 'P1' }
                return $null
            }
        }
    }
}
