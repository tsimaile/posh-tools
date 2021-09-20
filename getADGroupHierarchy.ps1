<#
.SYNOPSIS
    Recurse ADGroup for members and return object
.DESCRIPTION
    1. Recurse thourhg ADGroup for all users and groups
    2. Construct object with users and groups
    3. Return object
.NOTES
    Author:  ts-systech-team@scu.edu.au
    Created: 07-Sep-2021
    LastMod: 13-Sep-2021 - use SamAccountName to capture pre-Windows 2000 groupnames
.REFERENCE
    Inspire: https://community.idera.com/database-tools/powershell/ask_the_experts/f/active_directory__powershell_remoting-9/9588/displaying-a-nested-group-hierarchy
.EXAMPLE
    getADGroupHierarchy -adGroup grpAdmins
.EXAMPLE
    getADGroupHierarchy -adGroup grpFinance -adServer staff.domain -includeUsers
.EXAMPLE
    getADGroupHierarchy -adGroup grpFinance -adServer staff.domain | ConvertTo-Json -Depth 9 | Out-File C:\data\grpFinance.json
.PARAMETER adGroup
    The root AD group to recurse through
.PARAMETER adServer
    The domain server to source adGroup from
.PARAMETER includeUsers
    Switch to include users
    If not invoked, only group structure will be returned
#>

Import-Module ActiveDirectory
function getADGroupHierarchy {
    param (
        [Parameter(Mandatory=$true)]
        [String]$adGroup     # the root AD group name
        ,[String]$adServer = $ADServerStaff
        ,[switch]$includeUsers
    )

    begin {
        $members = Get-ADGroupMember -Identity $adGroup -Server $adServer

        if ($includeUsers.IsPresent) {
            $users = $members | Where-Object -Property objectClass -eq user | 
                Select-Object SamAccountName | 
                Sort-Object SamAccountName
        }

        $groups = $members |
            Where-Object -Property objectClass -eq group |
            Select-Object SamAccountName |
            Sort-Object SamAccountName
    }

    process {
        # add the root adGroup
        $out = @{
            $adGroup = @()
        }

        if ($includeUsers.IsPresent) {
            # add users in adGroup
            foreach ($user in $users.SamAccountName) {
                $out[$adGroup] += $user
            }
        }
    
        # add groups in adGroup and recurse thru sub-groups
        foreach ($group in $groups.SamAccountName) {
            $out[$adGroup] += @{
                $group = (getADGroupHierarchy -adGroup $group -adServer $adServer -includeUsers:$includeUsers.IsPresent)[$group]
            }
        }
    }

    end {
        return $out
    }
}