<#
.SYNOPSIS
    All Microsoft Entra privileged role assignments are managed with PIM
#>

function Test-Assessment-21816 {
    [ZtTest(
    	Category = 'Privileged access',
    	ImplementationCost = 'Medium',
    	MinimumLicense = ('P2'),
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Protect identities and secrets',
    	TenantType = ('Workforce'),
    	TestId = 21816,
    	Title = 'All Microsoft Entra privileged role assignments are managed with PIM',
    	UserImpact = 'Low'
    )]
    [CmdletBinding()]
    param()

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose
    if( -not (Get-ZtLicense EntraIDP2) ) {
        Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP2
        return
    }

    #region Data Collection
    $activity = 'Checking Microsoft Entra privileged role assignments are managed with PIM'
    Write-ZtProgress -Activity $activity

    $globalAdminRoleId = Get-ZtRoleInfo -RoleName 'GlobalAdministrator'
    $permanentGAUserList = @()
    $permanentGAGroupList = @()
    $nonPIMPrivilegedUsers = @()
    $nonPIMPrivilegedGroups = @()

    # Query 1: Find all privileged directory roles
    Write-ZtProgress -Activity $activity -Status 'Getting privileged directory roles'
    $privilegedRoles = Get-ZtRole -IncludePrivilegedRoles
    Write-PSFMessage "Found $($privilegedRoles.Count) privileged roles" -Level Verbose

    # Query 2: Check for eligible Global Administrators (PIM usage confirmation)
    Write-ZtProgress -Activity $activity -Status 'Checking eligible Global Administrators'
    try {
        $eligibleGAs = Invoke-ZtGraphRequest -RelativeUri 'roleManagement/directory/roleEligibilitySchedules' -Filter "roleDefinitionId eq '$globalAdminRoleId'" -ApiVersion beta
    }
    catch {
        if ($_ -match 'AadPremiumLicenseRequired|BadRequest') {
            Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP2
            return
        }
        throw
    }
    Write-PSFMessage "Found $($eligibleGAs.Count) eligible GA assignments" -Level Verbose

    $eligibleGAUsers = 0
    foreach ($eligibleGA in $eligibleGAs) {
        # Get principal information separately
        $principal = Invoke-ZtGraphRequest -RelativeUri "directoryObjects/$($eligibleGA.principalId)" -ApiVersion beta

        if ($principal.'@odata.type' -eq '#microsoft.graph.user') {
            $eligibleGAUsers++
        } elseif ($principal.'@odata.type' -eq '#microsoft.graph.group') {
            # Get group members for eligible GA groups
            $groupMembers = Invoke-ZtGraphRequest -RelativeUri "groups/$($principal.id)/members" -Select 'userPrincipalName,displayName,id' -ApiVersion beta
            $eligibleGAUsers += $groupMembers.Count
        }
    }

    # Process each privileged role (excluding Global Administrator for now)
    # Fetch PIM assignments per role in bulk (one call per role instead of per member)
    Write-ZtProgress -Activity $activity -Status 'Checking privileged role assignments'
    foreach ($role in $privilegedRoles) {
        if ($role.templateId -eq $globalAdminRoleId) { continue } # Skip GA, handle separately

        Write-PSFMessage "Processing role: $($role.displayName)" -Level Verbose
        $directoryRole = Invoke-ZtGraphRequest -RelativeUri 'directoryRoles' -Filter "roleTemplateId eq '$($role.templateId)'" -ApiVersion beta

        if ($directoryRole) {
            Write-PSFMessage "Found directory role instance for $($role.displayName)" -Level Verbose
            $roleMembers = Invoke-ZtGraphRequest -RelativeUri "directoryRoles/$($directoryRole.id)/members" -Select 'userPrincipalName,displayName,id' -ApiVersion beta
            Write-PSFMessage "Found $($roleMembers.Count) members in role $($role.displayName)" -Level Verbose

            # Bulk fetch all PIM assignments for this role (one API call instead of N)
            try {
                $rolePimAssignments = Invoke-ZtGraphRequest -RelativeUri 'roleManagement/directory/roleAssignmentScheduleInstances' -Filter "roleDefinitionId eq '$($role.templateId)'" -ApiVersion beta
            } catch {
                if ($_ -match 'AadPremiumLicenseRequired|BadRequest|Forbidden') {
                    Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP2
                    return
                }
                throw
            }
            $pimLookup = @{}
            foreach ($pa in $rolePimAssignments) {
                $pimLookup[$pa.principalId] = $pa
            }

            foreach ($member in $roleMembers) {
                $pimAssignment = $pimLookup[$member.id]
                Write-PSFMessage "PIM assignment check for $($member.displayName): Found=$($null -ne $pimAssignment)" -Level Verbose

                if (-not $pimAssignment -or ($pimAssignment.assignmentType -eq 'Assigned' -and $null -eq $pimAssignment.endDateTime)) {
                    $memberInfo = [PSCustomObject]@{
                        displayName = $member.displayName
                        userPrincipalName = $member.userPrincipalName
                        id = $member.id
                        roleTemplateId = $role.templateId
                        roleDefinitionId = $role.id
                        roleName = $role.displayName
                        isPrivileged = $true
                        assignmentType = if ($pimAssignment) { $pimAssignment.assignmentType } else { 'Not in PIM' }
                    }

                    if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                        $nonPIMPrivilegedUsers += $memberInfo
                    } else {
                        $nonPIMPrivilegedGroups += $memberInfo
                    }
                }
            }
        }
    }

    # Query 3: Handle Global Administrator role separately
    Write-ZtProgress -Activity $activity -Status 'Checking Global Administrator assignments'
    $gaDirectoryRole = Invoke-ZtGraphRequest -RelativeUri 'directoryRoles' -Filter "roleTemplateId eq '$globalAdminRoleId'" -ApiVersion beta

    if ($gaDirectoryRole) {
        $gaMembers = Invoke-ZtGraphRequest -RelativeUri "directoryRoles/$($gaDirectoryRole.id)/members" -Select 'userPrincipalName,displayName,id' -ApiVersion beta

        # Bulk fetch all PIM assignments for Global Administrator role
        try {
            $gaPimAssignments = Invoke-ZtGraphRequest -RelativeUri 'roleManagement/directory/roleAssignmentScheduleInstances' -Filter "roleDefinitionId eq '$globalAdminRoleId'" -ApiVersion beta
        } catch {
            if ($_ -match 'AadPremiumLicenseRequired|BadRequest|Forbidden') {
                Add-ZtTestResultDetail -SkippedBecause NotLicensedEntraIDP2
                return
            }
            throw
        }
        $gaPimLookup = @{}
        foreach ($pa in $gaPimAssignments) {
            $gaPimLookup[$pa.principalId] = $pa
        }

        foreach ($member in $gaMembers) {
            $pimAssignment = $gaPimLookup[$member.id]

            if (-not $pimAssignment -or ($pimAssignment.assignmentType -eq 'Assigned' -and $null -eq $pimAssignment.endDateTime)) {
                $memberInfo = [PSCustomObject]@{
                    displayName = $member.displayName
                    userPrincipalName = $member.userPrincipalName
                    id = $member.id
                    roleTemplateId = $globalAdminRoleId
                    roleDefinitionId = $gaDirectoryRole.id
                    roleName = 'Global Administrator'
                    isPrivileged = $true
                    assignmentType = if ($pimAssignment) { $pimAssignment.assignmentType } else { 'Not in PIM' }
                }

                if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                    $permanentGAUserList += $memberInfo
                } elseif ($member.'@odata.type' -eq '#microsoft.graph.group') {
                    $permanentGAGroupList += $memberInfo
                    $groupMembers = Invoke-ZtGraphRequest -RelativeUri "groups/$($member.id)/members" -Select 'userPrincipalName,displayName,id,onPremisesSyncEnabled' -ApiVersion beta
                    foreach ($groupMember in $groupMembers) {
                        if ($groupMember.'@odata.type' -eq '#microsoft.graph.user') {
                            $groupMemberInfo = [PSCustomObject]@{
                                displayName = $groupMember.displayName
                                userPrincipalName = $groupMember.userPrincipalName
                                id = $groupMember.id
                                roleTemplateId = $globalAdminRoleId
                                roleDefinitionId = $gaDirectoryRole.id
                                roleName = 'Global Administrator (via group)'
                                isPrivileged = $true
                                assignmentType = 'Via Group'
                                onPremisesSyncEnabled = $groupMember.onPremisesSyncEnabled
                            }
                            $permanentGAUserList += $groupMemberInfo
                        }
                    }
                }
            }
        }
    }
    #endregion Data Collection

    #region Assessment Logic
    Write-PSFMessage "Assessment data: EligibleGAUsers=$eligibleGAUsers, NonPIMPrivileged=$($nonPIMPrivilegedUsers.Count + $nonPIMPrivilegedGroups.Count), PermanentGA=$($permanentGAUserList.Count)" -Level Verbose

    $hasPIMUsage = $eligibleGAUsers -gt 0
    $hasNonPIMPrivileged = ($nonPIMPrivilegedUsers.Count + $nonPIMPrivilegedGroups.Count) -gt 0
    $permanentGACount = $permanentGAUserList.Count

    if (-not $hasPIMUsage) {
        $passed = $false
        $testResultMarkdown = 'No eligible Global Administrator assignments found. PIM usage cannot be confirmed.'
    } elseif ($hasNonPIMPrivileged) {
        $passed = $false
        $testResultMarkdown = 'Found Microsoft Entra privileged role assignments that are not managed with PIM.'
    } elseif ($permanentGACount -gt 2) {
        $passed = $false
        $customStatus = 'Investigate'
        $testResultMarkdown = 'Three or more accounts are permanently assigned the Global Administrator role. Review to determine whether these are emergency access accounts.'
    } else {
        $passed = $true
        $testResultMarkdown = 'All Microsoft Entra privileged role assignments are managed with PIM with the exception of up to two standing Global Administrator accounts.'
    }

    $testResultMarkdown += "`n`n%TestResult%"
    #endregion Assessment Logic

    #region Report Generation
    $mdInfo = ''

    # Always show summary information
    $mdInfo += "`n## Assessment summary`n`n"
    $mdInfo += "| Metric | Count |`n"
    $mdInfo += "| :----- | :---- |`n"
    $mdInfo += "| Privileged roles found | $($privilegedRoles.Count) |`n"
    $mdInfo += "| Eligible Global Administrators | $($eligibleGAUsers) |`n"
    $mdInfo += "| Non-PIM privileged users | $($nonPIMPrivilegedUsers.Count) |`n"
    $mdInfo += "| Non-PIM privileged groups | $($nonPIMPrivilegedGroups.Count) |`n"
    $mdInfo += "| Permanent Global Administrator users | $($permanentGAUserList.Count) |`n"

    if ($nonPIMPrivilegedUsers.Count -gt 0 -or $nonPIMPrivilegedGroups.Count -gt 0) {
        $mdInfo += "`n## Non-PIM managed privileged role assignments`n`n"
        $mdInfo += "| Display name | User principal name | Role name | Assignment type |`n"
        $mdInfo += "| :----------- | :------------------ | :-------- | :-------------- |`n"

        foreach ($user in $nonPIMPrivilegedUsers) {
            $userLink = "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/AdministrativeRole/userId/$($user.id)/hidePreviewBanner~/true"
            $safeDisplayName = Get-SafeMarkdown -Text $user.displayName
            $displayNameLink = "[$safeDisplayName]($userLink)"
            $mdInfo += "| $displayNameLink | $($user.userPrincipalName) | $($user.roleName) | $($user.assignmentType) |`n"
        }

        foreach ($group in $nonPIMPrivilegedGroups) {
            $groupLink = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/RolesAndAdministrators/groupId/$($group.id)/menuId/"
            $safeDisplayName = Get-SafeMarkdown -Text $group.displayName
            $displayNameLink = "[$safeDisplayName]($groupLink)"
            $mdInfo += "| $displayNameLink | N/A (Group) | $($group.roleName) | $($group.assignmentType) |`n"
        }
    }

    if ($permanentGAUserList.Count -gt 0) {
        $mdInfo += "`n## Permanent Global Administrator assignments`n`n"
        $mdInfo += "| Display name | User principal name | Assignment type | On-Premises synced |`n"
        $mdInfo += "| :----------- | :------------------ | :-------------- | :----------------- |`n"

        foreach ($user in $permanentGAUserList) {
            $syncStatus = if ($null -ne $user.onPremisesSyncEnabled) { $user.onPremisesSyncEnabled } else { 'N/A' }
            $userLink = "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/AdministrativeRole/userId/$($user.id)/hidePreviewBanner~/true"
            $safeDisplayName = Get-SafeMarkdown -Text $user.displayName
            $displayNameLink = "[$safeDisplayName]($userLink)"
            $mdInfo += "| $displayNameLink | $($user.userPrincipalName) | $($user.assignmentType) | $syncStatus |`n"
        }
    }

    $testResultMarkdown = $testResultMarkdown -replace '%TestResult%', $mdInfo
    #endregion Report Generation

    Add-ZtTestResultDetail -Status $passed -Result $testResultMarkdown
}
