function Get-ZtModuleCachePath {
    <#
    .SYNOPSIS
    Returns the path to the ZeroTrustAssessment required modules cache directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    if ($IsWindows) {
        Join-Path -Path $Env:APPDATA -ChildPath 'ZeroTrustAssessment' -AdditionalChildPath 'Modules'
    }
    else {
        Join-Path -Path $Env:HOME -ChildPath '.cache/ZeroTrustAssessment/Modules'
    }
}
