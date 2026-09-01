function Open-ZtReport {
    <#
    .SYNOPSIS
        Opens a generated assessment report with the platform's default application.

    .DESCRIPTION
        Opens a report on Windows, Linux, or macOS. Browser-launch failures are logged and
        returned as false so they cannot fail an otherwise completed assessment.

    .PARAMETER Path
        Path to the generated HTML report.

    .OUTPUTS
        Boolean indicating whether the report opener started successfully.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(DontShow)]
        [scriptblock]
        $OpenAction
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-PSFMessage -Message "Assessment report was not found at '$Path'." -Level Warning
        return $false
    }

    try {
        if ($OpenAction) {
            & $OpenAction $Path
        }
        elseif ($IsWindows) {
            Invoke-Item -LiteralPath $Path -ErrorAction Stop | Out-Null
        }
        else {
            $commandName = if ($IsMacOS) { 'open' } else { 'xdg-open' }
            $openCommand = Get-Command -Name $commandName -CommandType Application -ErrorAction Stop
            & $openCommand.Source $Path 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "'$commandName' exited with code $LASTEXITCODE."
            }
        }
        return $true
    }
    catch {
        Write-PSFMessage -Message "The assessment report could not be opened automatically. Open it manually at '$Path'." -Level Warning -ErrorRecord $_
        return $false
    }
}
