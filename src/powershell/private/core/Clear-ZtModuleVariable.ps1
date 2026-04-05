<#
.SYNOPSIS
    Resets all module variables to their default values.

.DESCRIPTION
    Variables like GraphCache and GraphBaseUri are module-level variables that are cached
    during the running of a test for performance reasons.

    This function will be called for each fresh run of Invoke-ZeroTrustAssessment.
#>

function Clear-ZtModuleVariable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Module variables used in other functions.')]
    [CmdletBinding()]
    param()

    $script:__ZtSession.GraphCache.Value.Clear()
    $script:__ZtSession.AzureCache.Value.Clear()
    $script:__ZtSession.GraphBaseUri = $null
    $script:__ZtSession.TestResultDetail.Value.Clear()
    $script:__ZtSession.TestStatistics.Value.Clear()
    $script:__ZtSession.TenantInfo.Value.Clear()
    $script:__ZtSession.SignInLogDuration = $null
    $script:__ZtSession.PreviewEnabled = $false
    $script:__ZtSession.CloudEnvironment = $null
    $script:ConnectedService = @()
    $script:__ZtLicensePlanIds = $null

    # Clear the thread-safe permission risk cache so stale data doesn't persist
    if ($script:_GraphPermissions -and $script:_GraphPermissions -is [System.Collections.Concurrent.ConcurrentDictionary[string, string]]) {
        $script:_GraphPermissions.Clear()
    }

    # Close any lingering module-managed database connection
    if ($script:_DatabaseConnection) {
        try { Disconnect-Database } catch { Write-PSFMessage "Failed to close lingering DB connection: $_" -Level Debug }
    }
}
