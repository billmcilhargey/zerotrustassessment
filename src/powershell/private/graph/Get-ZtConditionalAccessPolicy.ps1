<#
 .Synopsis
  Returns conditional access policies in the tenant.

 .Description
  Shared helper to query conditional access policies via Graph API.
  Defaults to v1.0 for stability; callers needing beta-only features can pass -ApiVersion beta.

 .Parameter Filter
  Optional OData filter expression (e.g. "state eq 'enabled'").

 .Parameter ApiVersion
  Graph API version to use. Defaults to v1.0 (least-privilege, stable).

 .Example
  Get-ZtConditionalAccessPolicy

 .Example
  Get-ZtConditionalAccessPolicy -Filter "state eq 'enabled'"

 .Example
  Get-ZtConditionalAccessPolicy -ApiVersion beta
#>

Function Get-ZtConditionalAccessPolicy {
  [CmdletBinding()]
  param(
    [string]$Filter,
    [ValidateSet('v1.0', 'beta')]
    [string]$ApiVersion = 'v1.0'
  )

  Write-PSFMessage -Message "Getting conditional access policies."

  $params = @{
    RelativeUri = 'identity/conditionalAccess/policies'
    ApiVersion  = $ApiVersion
  }
  if ($Filter) {
    $params.Filter = $Filter
  }

  return Invoke-ZtGraphRequest @params
}
