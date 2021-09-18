function getHash {
<#
.SYNOPSIS
    return hash from string
.DESCRIPTION
    input string and return md5, sh1, sha256, or sha512 as continguous lowercase string
#>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string]$string,                                # string to be hashed
        [ValidateSet("md5","sha1","sha256","sha512")]   # type of hash to get
        [string]$hashType,
        [switch]$upperCase                              # return in uppercase
    )
    
    $hash = $null

    switch ($hashType) {
        "md5" {
            # https://gist.github.com/dalton-cole/4b9b77db108c554999eb
            # converts string to MD5 hash in hyphenated and uppercase format
            $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = New-Object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($string)))
            # to remove hyphens and downcase letters add
            $hash = $hash.ToLower() -replace '-', ''
        }
        "sha1" {
            $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $utf8 = New-Object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($sha1.ComputeHash($utf8.GetBytes($string)))
            # to remove hyphens and downcase letters add
            $hash = $hash.ToLower() -replace '-', ''
        }
        "sha256" {
            # https://gist.github.com/benrobot/67bacea1b1bbe4eb0d9529ba2c65b2a6
            $hash = [string]::Join("", (New-Object System.Security.Cryptography.SHA256Managed | 
                ForEach-Object {$PSItem.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($string))} | 
                ForEach-Object {$PSItem.ToString("x2")} ))
        }
        "sha512" {
            $hash = [string]::Join("", (New-Object System.Security.Cryptography.SHA512Managed | 
                ForEach-Object {$PSItem.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($string))} | 
                ForEach-Object {$PSItem.ToString("x2")} ))
        }
    }

    if ($upperCase) {
        $hash = $hash.ToUpper()
    }
    return $hash
}