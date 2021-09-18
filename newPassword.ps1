function newPassword {
    <#
    .SYNOPSIS
        Generate passwords to policy specification
    .DESCRIPTION
        Generate passwords to policy specification
    .NOTES
        Author: TS SysTech Team (ts-systech-team@scu.edu.au)
        Created: 29-Jun-2018
        LastMod: 02-Jul-2018
    .EXAMPLE
        newPassword
        generates 1 password using default length and character set
    .EXAMPLE
        newPassword -type alphanumeric -length 31 -count 4 -upper ''
        generates 4 passwords of length 31 and of lower and numeric characters 
    .PARAMETER type
        pre-determined character set policy to apply to new passwords
    .PARAMETER length
        length of new passwords
    .PARAMETER count
        number of passwords to generate
    .PARAMETER unambiguous
        remove ambiguous characters        
    .PARAMETER upper
        uppercase alphabetic character set
    .PARAMETER lower
        lowercase alphabetic character set
    .PARAMETER number
        number character set
    .PARAMETER special
        special character set
    .PARAMETER noClipboard
        do not contents to 
    #>

    [CmdletBinding()]
    Param (
        [ValidateSet("oracle","hexadecimal","alphanumeric","all","numeric","alphabetic")] 
        [string]$type = 'oracle'
        ,[ValidateRange(4,999)]
        [int]$length = 20
        ,[int]$count = 1
        ,[int]$groupSize = 0
        ,[string]$groupSeparator = ' '
        ,[switch]$unambiguous
        ,[string]$upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ,[string]$lower   = "abcdefghijklmnopqrstuvwxyz"
        ,[string]$number  = "0123456789"
        ,[string]$special = "``~!@#$%^&*()-_=+|\}]{[`'`";:/?.>,<"
        ,[switch]$noClipboard
    )
    begin {
        # apply character sets based on password type
        switch ($type) {
            'oracle' {
                $special = "#_!" # shortened from http://banhill.hu/banhill/orapass_en.html (some chars removed due to script/platform/wildcard restrictions e.g. Bamboo)
                if ($length -gt 30) { 
                    $length = 30 # https://docs.oracle.com/database/121/DBSEG/authentication.htm#DBSEG33223
                    Write-Host "Oracle password length set to maximum of 30 characters" -ForegroundColor Yellow
                } 
            }
            'hexadecimal' {
                $upper   = 'ABCDEF'
                $lower   = ''
                $special = ''
            }
            'alphanumeric' {
                $special = ''
            }
            'alphabetic' {
                $number  = ''
                $special = ''
            }
            'numeric' {
                $upper   = ''
                $lower   = ''
                $special = ''
            }
            'all' {
            }
        }

        # build character set object
        $set = @{
            "upper"   = $upper;
            "lower"   = $lower;
            "number"  = $number;
            "special" = $special;
        }

        # remove ambiguous characters from sets
        if ($unambiguous) {
            $ambiguousSet = "0O1Il|5SZ2"
            foreach ($key in $($set.Keys)) {
                $set[$key] = $set[$key] -replace "[$ambiguousSet]"
            }
        }

        # define alphabetic characters
        $alpha = $set["upper"] + $set["lower"]

        # define all characters
        $all = ""
        foreach ($key in $set.Keys) {
            $all += $set[$key]
        }

        # check at least 1 character to work with
        if ($all.Length -lt 1) {
            throw 'Character set length < 1'
        }
    }

    process {
        $passwords = @()
        do {
            do {
                $password = ""
                $entropy = 0

                # fill to the required length
                while ($password.Length -lt $length) {
                    $password += $all.Substring((Get-Random -Maximum $all.Length), 1)
                }

                # shuffle per https://powershell.org/forums/topic/shuffle-a-string/
                $password = -join ($password -split '' | Sort-Object { Get-Random })

                # apply additional type policies
                switch ($type) {
                    'oracle' {
                        # replace first character with alpha
                        $password = $password -replace '^.',($alpha.ToCharArray() | Get-Random)
                    }
                }

            } until (
                # password has at least 1 character from each non-empty set
                $false -notin @(
                    foreach ($key in $set.Keys) {
                        if ([bool]$set[$key]) {
                            ($password.ToCharArray() | %{ $set[$key] -match [System.Text.RegularExpressions.Regex]::Escape($PSItem) }) -contains $true
                        }
                    }
                )
            )

            # calc the entropy bits per https://en.wikipedia.org/wiki/Password_strength#Entropy_as_a_measure_of_password_strength
            $entropy = [int]($password.Length * ( [System.Math]::Log($all.Length) / [System.Math]::Log(2) ))

            # apply character grouping to password
            if ($groupSize -gt 0) {
                $password = ([string]$($password -split "(.{$groupSize})" | ForEach-Object { if([bool]$PSItem) { $PSItem } })) -replace ' ',"$groupSeparator"
            }

            # add new password to passwords list
            $passwords += New-Object -TypeName psobject -Property @{
                "count"    = $passwords.Count + 1;
                "password" = $password;
                "type"     = $type;
                "length"   = $length;
                "entropy"  = $entropy;
            }
        } until ($passwords.Count -eq $count)
    }

    end {
        # copy last password to Windows clipboard
        if (-not $noClipboard) {
            if ([bool](Get-Command Set-Clipboard -ErrorAction SilentlyContinue)) {
                Set-Clipboard $password -Verbose
            }
        }
        # return to caller
        return $passwords |
            Select-Object -Property count,password,type,length,entropy 
    }
}