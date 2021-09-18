function getHash {

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string]$string,
        [ValidateSet(“md5”,"sha256","sha512")]
        [string]$hashType,
        [switch]$upperCase

    )
    
    $someString = $string
    $hash = $null

    switch ($hashType) {
        "md5" {
            # https://gist.github.com/dalton-cole/4b9b77db108c554999eb
            #converts string to MD5 hash in hyphenated and uppercase format
            $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = New-Object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($someString)))

            #to remove hyphens and downcase letters add:
            $hash = $hash.ToLower() -replace '-', ''
        }
        "sha256" {
            # https://gist.github.com/benrobot/67bacea1b1bbe4eb0d9529ba2c65b2a6
            $hash = [string]::Join("", (New-Object System.Security.Cryptography.SHA256Managed | ForEach-Object {$_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($someString))} | ForEach-Object {$_.ToString("x2")} ))
        }
        "sha512" {
            $hash = [string]::Join("", (New-Object System.Security.Cryptography.SHA512Managed | ForEach-Object {$_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($someString))} | ForEach-Object {$_.ToString("x2")} ))
        }
    }

    if ($upperCase) {
        $hash = $hash.ToUpper()
    }
    return $hash
}