<#
.SYNOPSIS
    invokeBenchMark
.DESCRIPTION
    1. Copy benchmark script to server
    2. invoke benchmark on server and return results
.NOTES
    Author:  ts-systech-team@scu.edu.au
    Created: 27-Sep-2021
    LastMod: 15-Feb-2023 - use resolveServer2 function
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
            $cn = $server.computername.Trim()
            $src = (Get-ChildItem -Path $medir -Filter "*$type*").FullName
            $dst = "\\$cn\C$\Users\Public\Downloads\"
            $pscred = getCredential -asUser $server.user

            #$cn, $src, $dst
        }
        process {
            # copy benchmark script to server
            writeLog "Processing $cn ..."
            #copyFile -path $src -destination $dst
            if (Test-Path -Path $dst -ErrorAction SilentlyContinue) {
                if (Test-WSMan -ComputerName $cn -ErrorAction SilentlyContinue) {
                    Copy-Item -Path $src -Destination $dst
                    # invoke benchmanrk script on server and return result
                    $path = Join-Path $dst -ChildPath (Split-Path -Path $src -Leaf)
                    $result = Invoke-Command -ComputerName $cn -Credential $pscred -ArgumentList $path -ScriptBlock {
                            param ($dstPath)
                            & $dstPath
                        }
                } else {
                    writeLog "- Test-WSMan $cn = FAIL"
                    $result = New-Object -TypeName psobject -Property @{
                        "ComputerName" = $cn;
                        "BenchMark" = $type;
                        "Pass" = "UNKNOWN";
                        "Recommendation" = "NULL";
                        "Note" = "Test-WSMan = FAIL";
                    }
                }
            } else {
                writeLog "- Test-Path $cn = FAIL"
                $result = New-Object -TypeName psobject -Property @{
                    "ComputerName" = $cn;
                    "BenchMark" = $type;
                    "Pass" = "UNKNOWN";
                    "Recommendation" = "NULL";
                    "Note" = "Test-Path = FAIL";
                }
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
            [string]$filter,
            [string]$app = ".",
            [string]$env = ".",
            [string]$svc = ".",
            [switch]$exportCsv
        )
        begin {
            $params = "-type $type"
            if ([bool]$filter) {$params += " -filter $filter"}
            if ([bool]$app)    {$params += " -app $app"}
            if ([bool]$env)    {$params += " -env $env"}
            if ([bool]$svc)    {$params += " -svc $svc"}

            writeLog "BEGIN $me $params"

            # local vars
            $servers = resolveServer2 -filter $filter -app $app -env $env -svc $svc -unique
        }
        process {
            $results = @()
            foreach ($server in $servers) {
                $results += invokeBenchMarkOnServer -server $server -type $type
            }
        }
        end {
            if ([bool]$exportCsv) {
                $csvFile = Join-Path $dataPath -ChildPath "$now-benchmark-$type.csv"
                $results |
                    Select-Object ComputerName, BenchMark, Pass, Recommendation, Note |
                    Export-Csv -Path $csvFile -NoTypeInformation -Append
                writeLog "Export-Csv -Path $csvFile -NoTypeInformation -Append"
            }
            return $results
        }
    }

    function assessBenchMark {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)][ValidateSet("cis-iis","cis-sql")][string]$type
        )
        begin {
            $path = Get-ChildItem -Path $dataPath -Filter "*$type*" |
                Sort-Object -Property LastWriteTime |
                Select-Object -Last 1
            $raw = Import-Csv -Path $path.FullName
        }
        process {
            $count = ($raw | Select-Object -Property ComputerName -Unique).count

            writeLog "$type Server Count = $count"
            return $raw |
                Where-Object -Property Pass -eq $false |
                Select-Object -Property ComputerName, Recommendation -Unique |
                Group-Object -Property Recommendation |
                Select-Object Count, Name |
                Sort-Object Count -Descending
        }
        end {

        }
    }
}

process {
}

end {
}