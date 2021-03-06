function copyFile {
    <#
    .SYNOPSIS
        robocopy as Powershell function
    .DESCRIPTION
        copy/move files from source to destination
        options always used:
            /e Copies subdirectories. Note that this option includes empty directories.
            /r:2 number of retries on failed copies
    .NOTES
        Author: Tim Simaile (TSO;SCU)
        Created: 12-Jan-2013
        LastMod: 15-Aug-2017
    .EXAMPLE
        copyFile -path "\\staff.domain\software\release\" -destination "\\student.domain\software\public\"
    .EXAMPLE
        copyFile `
            -path $src_ci `
            -destination $trg_ci `
            -excludeDirectory @("configfiles",
                "software\Custom",
                "software\Distribution",
                "software\licensing") `
            -mirror
    .PARAMETER path
        (mandatory) Specifies the path to the source directory.
    .PARAMETER destination
        (mandatory) Specifies the path to the destination directory.
    .PARAMETER filter
        (optional) Specifies the file or files to be copied. You can use wildcard characters (* or ?), if you want. If the File parameter is not specified, *.* is used as the default value.
    .PARAMETER includeEmpty
        (optional switch) /e Copies subdirectories. Note that this option includes empty directories.
        Dynamic with -recurse
    .PARAMETER recurse
        (optional switch) /s Copies subdirectories. Note that this option excludes empty directories.
    .PARAMETER mirror
        (optional switch) /purge Deletes destination files and directories that no longer exist in the source. 
    .PARAMETER move
        (optional switch) /move Moves files and directories, and deletes them from the source after they are copied. 
    .PARAMETER excludeFilter
        (optional) array of file filters; e.g. @("*.log","log*.*")
        /xf Excludes files that match the specified names or paths. Note that FileName can include wildcard characters (* and ?).
    .PARAMETER excludeDirectory
        (optional) array of directory names/paths (concat with -path); e.g. @("archive","data\temp")
        /xd Excludes directories that match the specified names and paths.
        Dynamic with -recurse
    .PARAMETER whatIf
        (optional switch) /l files are to be listed only (and not copied, deleted, or time stamped)
    .PARAMETER verbose
        (optional switch) /v produces verbose output, and shows all skipped files
    .REFERENCE
        https://technet.microsoft.com/en-us/library/cc733145(v=ws.11).aspx
        https://ss64.com/nt/robocopy.html
        https://blogs.technet.microsoft.com/heyscriptingguy/2011/05/15/simplify-your-powershell-script-with-parameter-validation/
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)][string]$path # Specifies the path to the source directory (or file).
        ,[Parameter(Mandatory=$True)][string]$destination # Specifies the path to the destination directory.
        ,[array] $filter = @("*.*") # Specifies the file or files to be copied. You can use wildcard characters (* or ?), if you want.
        #copy options
            #,[switch]$includeEmpty # Copies subdirectories. Note that this option includes empty directories.
            ,[switch]$recurse # Copies subdirectories. Note that this option includes empty directories.
            ,[switch]$mirror # Deletes destination files and directories that no longer exist in the source. 
            ,[switch]$move # Moves files, and deletes them from the source after they are copied.
        # file selection options
            ,[array] $excludeFilter = $null # Excludes files that match the specified names or paths. Note that FileName can include wildcard characters (* and ?).
            #,[array] $excludeDirectory = $null # Excludes directories that match the specified names and paths.
            ,[switch]$excludeOlder # Excludes older files.
            ,[datetime]$lastWriteAfter = (Get-Date 0) # Specifies the maximum file age (to exclude files older than N days or date).
            ,[datetime]$lastWriteBefore = (Get-Date).AddDays(1).Date # Specifies the minimum file age (to exclude files older than N days or date).
        # logging options
            ,[switch]$showProgress # Specifies that the progress of the copying operation (the number of files or directories copied so far) will be displayed.
            ,[string]$logFile = $null
            ,[switch]$hideHeader # Specifies that there is no job header.
            ,[switch]$hideFooter # Specifies that there is no job summary.
            ,[switch]$whatIf # Specifies that files are to be listed only (and not copied, deleted, or time stamped).
    )
    DynamicParam {
        # https://stackoverflow.com/questions/42318419/powershell-using-dynamic-parameters-value
        if ($recurse) {
            $runTimeDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $paramAttribute = New-Object System.Management.Automation.ParameterAttribute
            $attributeCollection.add($paramAttribute)
            
            $parameterName = 'includeEmpty'
            $runTimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter($parameterName, [switch], $attributeCollection)
            $runTimeDictionary.Add($ParameterName, $RunTimeParam)

            $parameterName = 'excludeDirectory'
            $runTimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter($parameterName, [array], $attributeCollection)
            $runTimeDictionary.Add($ParameterName, $RunTimeParam)

            return $runTimeDictionary
        }
    }

    begin {

        # local vars
            $cmdRobocopy     = "robocopy.exe" # robocopy executable
            $cmdDateFormat   = "yyyyMMdd"     # /maxage and /minage format
            $lastWriteFormat = "yyyy-MM-dd"   # -lastWriteAfter and -lastWriteBefore format

        # build writeLog arguments
            $logArguments = ""
            if ($filter -ne "*.*")                         { $logArguments += " -filter $([string]$filter)" }
            if ([bool]$PSBoundParameters['excludeFilter']) { $logArguments += " -excludeFilter $([string]$PSBoundParameters['excludeFilter'])" }
            if ([bool]$excludeDirectory)                   { $logArguments += " -excludeDirectory $([string]$excludeDirectory)" }
            if ($lastWriteAfter -gt (Get-Date 0))          { $logArguments += " -lastWriteAfter $(Get-Date $lastWriteAfter -f $lastWriteFormat)" }
            if ($lastWriteBefore -lt (Get-Date).Date)      { $logArguments += " -lastWriteBefore $(Get-Date $lastWriteBefore -f $lastWriteFormat)" }
        
            $argumentSwitches = @{
                " -recurse"      = $recurse;
                " -includeEmpty" = $PSBoundParameters['includeEmpty'];
                " -mirror"       = $mirror;
                " -move"         = $move;
                " -excludeOlder" = $excludeOlder;
                " -showProgress" = $showProgress;
                " -hideHeader"   = $hideHeader;
                " -hideFooter"   = $hideFooter;
                " -whatIf"       = $whatIf;
                " -verbose"      = $PSBoundParameters['Verbose'];
            }
            foreach ($argumentSwitch in $argumentSwitches.Keys | Sort-Object) {
                if ($argumentSwitches[$argumentSwitch]) { $logArguments += $argumentSwitch }
            }
        Write-Host "BEGIN copyFile -path $path -destination $destination$logArguments" -ForegroundColor Green
        
        # validate -path exists and check type
            if (-not (Test-Path $path)) {
                Write-Error "Invalid : Test-Path $path = FALSE -> throw"
                throw
            } else {
                # check -path type is file
                if ([bool]((Get-Item $path).DirectoryName)) {
                    # $path is file
                    $filter = Split-Path $path -Leaf
                    $path   = Split-Path $path -Parent
                    Write-Warning "-path type is file -> -path=`'$path`'; -filter=`'$filter`'"
                }
            }
        # validate -filter contains *.*
            if ($filter.count -gt 1) {
                if ("*.*" -in $filter) {
                    $filter = @("*.*") 
                    Write-Warning "'*.*' -IN -filter -> new -filter='*.*'"
                }
            }
        # validate -lastWriteAfter -lt -lastWriteBefore
            if ($lastWriteAfter -ge $lastWriteBefore) {
                Write-Error "Invalid : -lastWriteAfter -GE -lastWriteBefore -> throw"
		        throw
            }
        # validate -mirror -and -move
            if ($mirror -and $move) {
                Write-Error "Invalid : -mirror -AND -move -> throw"
	    	    throw
            }
        # validate '*.*' -in -excludeFilter
            if (("*.*" -in $excludeFilter) -and -not($recurse -and $PSBoundParameters['includeEmpty'])) {
                Write-Error "Invalid : ('*.*' -IN -excludeFilter) -AND -NOT(-recurse -AND -includeEmpty) -> THROW"
		        throw
            }
    }

    process {

        # parameters
            $cmdArguments = @(
                $path, # Specifies the path to the source directory.
                $destination # Specifies the path to the destination directory.
            )
            foreach ($fileFilter in $filter) {
                $cmdArguments += $fileFilter # Specifies the file or files to be copied. You can use wildcard characters (* or ?), if you want.
            }

        # copy options
            if ($recurse) { 
                if ($PSBoundParameters['includeEmpty']) {
                    $cmdArguments += "/e" # Copies subdirectories. Note that this option includes empty directories.
                } else {
                    $cmdArguments += "/s" # Copies subdirectories. Note that this option excludes empty directories.
                }
            } 
            if ($mirror)  { $cmdArguments += "/mir" } # Deletes destination files and directories that no longer exist in the source.
            if ($move)    { $cmdArguments += "/move" } # Moves files and directories, and deletes them from the source after they are copied.

        # file selection options
            if ([bool]$excludeFilter) { 
                $cmdArguments += "/xf" # Excludes files that match the specified names or paths. Note that FileName can include wildcard characters (* and ?).
                foreach ($xFilter in $excludeFilter) {
                    $cmdArguments += "$xFilter"
                }
            }
            if ([bool]$PSBoundParameters['excludeDirectory']) { 
                $cmdArguments += "/xd" # Excludes directories that match the specified names and paths.
                foreach ($xDirectory in $PSBoundParameters['excludeDirectory']) {
                    $cmdArguments += "$(Join-Path -Path $path -ChildPath $xDirectory)"
                }
            }
            if ($excludeOlder) { $cmdArguments += "/xo" } # Excludes older files.
            if ($lastWriteAfter -gt (Get-Date 0)) { $cmdArguments += "/maxage:$(Get-Date $lastWriteAfter -f $cmdDateFormat)" } 
            if ($lastWriteBefore -lt (Get-Date).AddDays(1).Date) { $cmdArguments += "/minage:$(Get-Date $lastWriteBefore -f $cmdDateFormat)" }
        
        # retry options
            $cmdArguments += "/r:2" # Specifies the number of retries on failed copies.
            $cmdArguments += "/w:5" # Specifies the wait time between retries, in seconds.

        # logging options
            if ($whatIf) { $cmdArguments += "/l" } # Specifies that files are to be listed only (and not copied, deleted, or time stamped).
            if ($PSBoundParameters['Verbose']) {
                $cmdArguments += "/x" # Reports all extra files, not just those that are selected.
                $cmdArguments += "/v" # Produces verbose output, and shows all skipped files.
            } else {
                $cmdArguments += "/ndl" # Specifies that directory names are not to be logged.
            }
            $cmdArguments += "/ts" # Includes source file time stamps in the output.
            $cmdArguments += "/fp" # Includes the full path names of the files in the output.
            if (-not $showProgress) { $cmdArguments += "/np" } # Specifies that the progress of the copying operation (the number of files or directories copied so far) will not be displayed.
            if ([bool]$logFile) { $cmdArguments += "/unilog+:$logFile" } # Writes the status output to the log file as Unicode text (appends the output to the existing log file).
            $cmdArguments += "/tee" # Writes the status output to the console window, as well as to the log file.
            if ($hideHeader) { $cmdArguments += "/njh" } # Specifies that there is no job header.
            if ($hideFooter) { $cmdArguments += "/njs" } # Specifies that there is no job summary.

        # invoke robocopy command with arguments
            Invoke-Command -ScriptBlock { & $cmdRobocopy $cmdArguments }
            Write-Host "Invoke-Command & $cmdRobocopy $([string]$cmdArguments)"
    }
    
    end {
        Write-Host "END copyFile"
    }
}