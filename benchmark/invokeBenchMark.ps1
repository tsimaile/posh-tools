<#
.SYNOPSIS
    invokeBenchMark
.DESCRIPTION
    1. Copy benchmark script to server
    2. invoke benchmark on server and return results
.NOTES
    Author:  ts-systech-team@scu.edu.au
    Created: 27-Sep-2021
    LastMod: 27-Sep-2021 - initial build
.REFERENCE
    https://www.cisecurity.org/cis-benchmarks/
#>

begin {
    # load commons
    $global:me = (($MyInvocation.MyCommand).Definition)
    . $(Join-Path (Split-Path (Split-Path $me -Parent) -Parent) common\common.ps1)

    function invokeBenchMarkOnServer {
        [CmdletBinding()]
        param (
            $server,
            $type
        )
        begin {
            # local vars
            $result = @()
            $cn = $server.computername
            $src = (Get-ChildItem -Path $medir -Filter "*$type*").FullName
            $dst = "\\$cn\C$\Users\Public\Downloads\"
            $pscred = getCredential -asUser $server.user

            $cn, $src, $dst
        }
        process {
            # copy benchmark script to server
            copyFile -path $src -destination $dst
            # invoke benchmanrk script on server and return result
            $path = Join-Path $dst -ChildPath (Split-Path -Path $src -Leaf)
            $result = Invoke-Command -ComputerName $cn -Credential $pscred -ArgumentList $path -ScriptBlock {
                    param ($dstPath)
                    & $dstPath
                }
        }
        end {
            return $result
        }
    }

    function invokeBenchMark {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)][ValidateSet("cis-iis","cis-sql")][string]$type,
            [string]$computernamefilter,
            [string]$application,
            [string]$environment,
            [string]$service
        )
        begin {
            $params = "-type $type"
            if ([bool]$computernamefilter) {$params += " -filter $computernamefilter"}
            if ([bool]$application)        {$params += " -application $application"}
            if ([bool]$environment)        {$params += " -environment $environment"}
            if ([bool]$service)            {$params += " -service $service"}

            writeLog "BEGIN $me $params"

            # local vars
            $servers = resolveServer -filter $computernamefilter -application $application -environment $environment -service $service -unique
        }
        process {
            $results = @()
            foreach ($server in $servers) {
                $results += invokeBenchMarkOnServer -server $server -type $type
            }
        }
        end {
            return $results
        }
    }
}

process {

}

end {

}