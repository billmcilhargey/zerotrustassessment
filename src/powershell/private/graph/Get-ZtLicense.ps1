<#
.SYNOPSIS
    Checks if a specific license is enabled in the tenant.

.DESCRIPTION
    Helper method that returns a boolean value check for specific license in the tenant.

.PARAMETER Product
    The Microsoft 365 product for which to retrieve the license information.

.EXAMPLE
    Get-ZtLicenseInformation -Product EntraIDP1
#>

function Get-ZtLicense {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('EntraIDP1', 'EntraIDP2', 'EntraIDGovernance', 'EntraWorkloadID', 'Intune')]
        [string] $Product
    )

    process {
        $skus = Get-ZtActiveServicePlanId
        $sp = $script:ZtServicePlanIds

        switch ($Product) {
            'EntraIDP1'        { return $sp.EntraIDP1 -in $skus }
            'EntraIDP2'        { return $sp.EntraIDP2 -in $skus }
            'EntraIDGovernance' { return $sp.EntraIDGovernance -in $skus }
            'EntraWorkloadID'  { return $sp.WorkloadIDP1 -in $skus -or $sp.WorkloadIDP2 -in $skus }
            'Intune'           { return $sp.IntuneP1 -in $skus -or $sp.IntuneP1Education -in $skus }
            Default            { return $false }
        }
    }
}
