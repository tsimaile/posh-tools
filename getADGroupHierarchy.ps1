# https://community.idera.com/database-tools/powershell/ask_the_experts/f/active_directory__powershell_remoting-9/9588/displaying-a-nested-group-hierarchy

Import-Module ActiveDirectory
function getADGroupHierarchy {
    param (
        [Parameter(Mandatory=$true)]
        [String]$root,      # the starting AD group name
        $indentChar = "`t", # the indenting character (default = Tab)
        $indentLead = "+ ", # the leading character after indent before groupname
        $indentCount = 0    # how many indentChars to insert
    )

    Write-Host ($indentChar * $indentCount)$indentLead$root

    $subgroups = Get-ADGroupMember $root |
        Where-Object -Property objectClass -eq group |
        Select-Object Name |
        Sort-Object Name
    foreach ($subGroup in $subGroups.Name) {
        # recurse thru sub-groups to find sub-sub-groups
        getADGroupHierarchy -root $subgroup -indentCount ($indentCount + 1)
    }
}