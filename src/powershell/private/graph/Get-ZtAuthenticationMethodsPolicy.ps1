<#
 .Synopsis
  Returns the authentication methods policy for the tenant.

 .Description
  Shared helper to retrieve the authentication methods policy via Graph API.
  Caches results through Invoke-ZtGraphRequest to avoid redundant API calls.

 .Parameter ApiVersion
  Graph API version. Defaults to v1.0; use beta for properties only in beta
  (e.g. policyMigrationState, reportSuspiciousActivitySettings).

 .Example
  Get-ZtAuthenticationMethodsPolicy

 .Example
  Get-ZtAuthenticationMethodsPolicy -ApiVersion beta
#>

Function Get-ZtAuthenticationMethodsPolicy {
  [CmdletBinding()]
  param(
    [ValidateSet('v1.0', 'beta')]
    [string]$ApiVersion = 'v1.0'
  )

  Write-PSFMessage -Message "Getting authentication methods policy."

  return Invoke-ZtGraphRequest -RelativeUri 'policies/authenticationMethodsPolicy' -ApiVersion $ApiVersion
}
