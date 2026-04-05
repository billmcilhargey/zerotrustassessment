function Add-DelegatePermissions {
    <#
    .SYNOPSIS
        Adds delegate (oauth2) permissions to one or more service principal items.

    .DESCRIPTION
        Queries oauth2PermissionGrants for the given items in a single bulk query
        and attaches a DelegatePermissions property to each item.

    .PARAMETER Items
        One or more items (hashtables or objects) with an 'id' property (ServicePrincipal id).

    .PARAMETER Database
        Database connection.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Items,

        [Parameter(Mandatory = $true)]
        $Database
    )

    # Normalise to array
    if ($Items -isnot [System.Collections.IEnumerable] -or $Items -is [hashtable]) {
        $Items = @($Items)
    }
    if ($Items.Count -eq 0) { return $Items }

    # Build a safe IN clause from GUIDs only
    $ids = @($Items | ForEach-Object {
        $id = if ($_ -is [hashtable]) { $_['id'] } else { $_.id }
        if ($id) { "'$($id.ToString().Replace("'", "''"))'" }
    }) | Where-Object { $_ }

    if ($ids.Count -eq 0) { return $Items }

    $inClause = $ids -join ','

    $sql = @"
    select sp.id as spId, sp.oauth2PermissionGrants.scope as permissionName
    from main.ServicePrincipal sp
    where sp.oauth2PermissionGrants.scope is not null
    and sp.id in ($inClause)
"@
    $results = Invoke-DatabaseQuery -Database $Database -Sql $sql

    # Build lookup: spId → list of permission names
    $lookup = @{}
    foreach ($r in $results) {
        $key = "$($r.spId)"
        if ($r.permissionName) {
            $perms = $r.permissionName.Trim() -replace '"', ''
            $permList = @($perms -split ' ' | Where-Object { -not [string]::IsNullOrEmpty($_) })
            if (-not $lookup[$key]) { $lookup[$key] = [System.Collections.Generic.List[string]]::new() }
            foreach ($p in $permList) { $lookup[$key].Add($p) }
        }
    }

    # Attach to each item
    foreach ($item in $Items) {
        $id = if ($item -is [hashtable]) { $item['id'] } else { $item.id }
        $item.DelegatePermissions = if ($lookup["$id"]) { @($lookup["$id"]) } else { @() }
    }

    return $Items
}
