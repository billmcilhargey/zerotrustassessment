function Add-AppPermissions {
    <#
    .SYNOPSIS
        Adds application (app role) permissions to one or more service principal items.

    .DESCRIPTION
        Queries app role assignments for the given items in a single bulk query
        and attaches an AppPermissions property to each item.

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
    select distinct sp.id as spId, spAppRole.permissionName
    from (select sp.id, unnest(sp.appRoleAssignments).AppRoleId as appRoleId
        from main.ServicePrincipal sp
        where sp.id in ($inClause)) sp
        left join
            (select unnest(main.ServicePrincipal.appRoles).id as id, unnest(main.ServicePrincipal.appRoles)."value" permissionName
            from main.ServicePrincipal) spAppRole
            on sp.appRoleId = spAppRole.id
    where spAppRole.permissionName is not null
"@
    $results = Invoke-DatabaseQuery -Database $Database -Sql $sql

    # Build lookup: spId → list of permission names
    $lookup = @{}
    foreach ($r in $results) {
        $key = "$($r.spId)"
        if (-not $lookup[$key]) { $lookup[$key] = [System.Collections.Generic.List[string]]::new() }
        $lookup[$key].Add($r.permissionName)
    }

    # Attach to each item
    foreach ($item in $Items) {
        $id = if ($item -is [hashtable]) { $item['id'] } else { $item.id }
        $item.AppPermissions = if ($lookup["$id"]) { @($lookup["$id"]) } else { @() }
    }

    return $Items
}
