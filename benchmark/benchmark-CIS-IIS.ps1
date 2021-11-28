<#
.SYNOPSIS
    invokeBenchMark-CIS-IIS
.DESCRIPTION
    1. This script copied to server by invokeBenchMark.ps1
    2. Run benchmark and return results as PSCustomObject
.NOTES
    Author:  ts-systech-team@scu.edu.au
    Created: 27-Sep-2021
    LastMod: 02-Nov-2021 - fix apostrophes
.REFERENCE
    https://www.cisecurity.org/cis-benchmarks/
#>

$raw = @()
$cn = $env:COMPUTERNAME
$bm = "CIS_IIS10_v1.1.1"

$results = Get-Website | Select-Object Name, PhysicalPath
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.1 Ensure web content is on non-system partition";
        "Pass" = $(
            if (
                ($result.PhysicalPath | Select-String -Pattern "SystemDrive") -eq $null -and
                ($result.PhysicalPath | Select-String -Pattern $env:SystemDrive) -eq $null
            ) { $true } else { $false }
        );
        "Note" = "Site = $($result.Name); Path = $($result.PhysicalPath);";
    }
}

$results = Get-Website |
    Get-WebBinding -Port * 
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.2 Ensure 'host headers' are on all sites ";
        "WebSiteName" = $PSItem.Name;
        "Pass" = $(
            if (
                $result.bindingInformation -ne '*:80:'
            ) { $true } else { $false }
        );
        "Note" = "Binding = $($result.bindingInformation);";
    } 
}

$results = Get-Website | % {
    Get-WebConfigurationProperty -Filter 'system.webserver/directorybrowse' -PSPath "IIS:\Sites\$($PSItem.Name)" -Name Enabled
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.3 Ensure 'directory browsing' is set to disabled";
        "Pass" = -not($result.Value);
        "Note" = "directoryBrowse = $($result.Value);"
    }
}

$results = Get-ChildItem -Path IIS:\AppPools\ |
    Select-Object name, state, @{e={$PSItem.processModel.identityType};l="identityType"}, @{e={$PSItem.processModel.UserName};l="UserName"}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.4 Ensure 'application pool identity' is configured for all application pools";
        "Pass" = $(
            If ( 
                $result.IdentityType -eq 'ApplicationPoolIdentity' 
            ) { $true } Else { $false }
        )
        "Note" = "AppPool = $($result.Name); Type = $($result.identityType); UserName = $($result.UserName);";
    }
}

$results = Get-WebApplication | Group-Object -Property 'applicationPool' | 
    Select-Object Name, Count |
    Sort-Object Name 
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.5 Ensure 'unique application pools' is set for sites";
        #"AppPoolName" = $PSItem.Name;
        "Pass" = $(
            if (
                $result.count -eq 1
            ) { $true } else { $false }
        );
        "Note" = "AppPool = $($result.Name); Count = $($result.count);";
    }
}

$results = Get-WebConfiguration -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Recurse |
    Where-Object -Property Enabled -EQ $true |
    Select-Object Location, userName
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.6 Ensure 'application pool identity' is configured for anonymous user identity";
        #"WebsiteName" = $PSItem.Name;
        "Pass" = $(
            If(
                $result.userName -EQ ''
            ) { $true } Else { $false }
        );
        "Note" = "Location = `'$($result.Location)`'; userName = `'$($result.userName)`';";
    }
}

$results = Get-WindowsFeature -name Web-DAV-Publishing
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.7 Ensure WebDav feature is disabled";
        "Pass" = -not($results.Installed);
    }

if ((Get-WindowsFeature Web-Url-Auth).Installed -EQ $true) {
    #Get-WebSite | ForEach-Object {
    #    $site = $PSItem.Name
    #    $config = Get-WebConfiguration -Filter "system.webServer/security/authorization" -PSPath "IIS:\Sites\$($PSItem.Name)" 
    $results = Get-Website | % {
        Get-WebConfiguration -Filter "system.webServer/security/authorization" -PSPath "IIS:\Sites\$($PSItem.Name)"
    }
    foreach ($result in $results) {
        $result.GetCollection() | ForEach-Object {
            $accessType = ($PSItem.Attributes | Where-Object Name -EQ 'accessType').Value
            $users = ($PSItem.Attributes | Where-Object Name -EQ 'users').Value
            $roles = ($PSItem.Attributes | Where-Object Name -EQ 'roles').Value

            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "2.1 Ensure 'global authorization rule' is set to restrict access";
                #"WebsiteName" = $site;
                #"AccessType" = $accessType;
                #"Users" = $users;
                #"Roles" = $roles;
                "Pass" = $(
                    if (
                        ($accessType -eq "Allow" -or $accessType -eq 0) -And ($users -eq "*" -or $roles -eq "?")
                    ) { $true } else { $false }
                );
                "Note" = "Site = `'$site`'; accessType = `'$accessType`'; users = `'$users`'; roles = `'$roles`';"
            }
        }
    }
} else {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.1 Ensure 'global authorization rule' is set to restrict access";
        "Pass" = $true;
        "Note" = "Web-Url-Auth not installed;"
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/authentication' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.2 Ensure access to sensitive site features is restricted to authenticated principals only";
        "Pass" = $(
            if (
                $result.mode -notin ('forms','Windows')
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; mode = `'$($result.mode)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/authentication/forms' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.3 Ensure 'forms authentication' requires SSL";
        "Pass"  = $result.requireSSL;
        "Note" = "PSPath = `'$($result.PSPath)`'; mode = `'$($result.ElementTagName)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/authentication/forms' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.4 Ensure 'forms authentication' is set to use cookies";
        "Pass"  = $(
            if (
                $result.cookieless -eq 'UseCookies'
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; cookieless = `'$($result.cookieless)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/authentication/forms' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.5 Ensure 'cookie protection mode' is configured for forms authentication";
        "Pass"  = $(
            if (
                $result.protection -eq 'All'
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; protection = `'$($result.protection)`';";
    }
}

$basicAuth = (Get-WebConfigurationProperty -filter "/system.WebServer/security/authentication/basicAuthentication" -name Enabled -PSPath "IIS:\sites\$($PSItem.Name)").Value
if ($basicAuth) {
    $results = Get-Website | %{
        Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/access' -Recurse 
    }
    foreach ($result in $results) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.6 Ensure transport layer security for 'basic authentication' is configured";
            "Pass"  = $(
                if (
                    $result.sslFlags -eq 'Ssl'
                ) { $true } else { $false }
            );
            "Note" = "PSPath = `'$($result.PSPath)`'; sslFlags = `'$($result.sslFlags)`';";
        }
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $psitem.PSPath -filter 'system.web/authentication/forms/credentials' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.7 Ensure 'passwordFormat' is not set to clear";
        "Pass" = $(
            if (
                $result.passwordFormat -ne 'clear'
            ){ $true } Else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; passwordFormat = `'$($result.passwordFormat)`';";
    }
}

$results = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration().GetSection("system.web/authentication").Forms
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.7 Ensure 'passwordFormat' is not set to clear";
        "Pass" = $(
            if (
                $result.Credentials.PasswordFormat -ne 'clear'
            ){ $true } Else { $false }
        );
        "Note" = "PSPath = `'MACHINE/`'; passwordFormat = `'$($result.Credentials.PasswordFormat)`';";
    }
}


$results = Get-Website | %{
    Get-WebConfiguration -PSPath $psitem.PSPath -filter 'system.web/authentication/forms/credentials' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.8 Ensure 'credentials' are not stored in configuration files";
        "Pass" = $(
            if (
                $result.User.Count -eq 0
            ){ $true } Else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; User.Count = `'$($result.User.Count)`';";
    }
}

$results = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration().GetSection("system.web/deployment")
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.1 Ensure 'deployment method retail' is set";
        "Pass" = $result.Retail;
        "Note" = "PSPath = `'MACHINE/`'; deployment.retail = `'$($result.Retail)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter '/system.web/compilation' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.2 Ensure 'debug' is turned off";
        "Pass" = -not($result.debug);
        "Note" = "PSPath = `'$($result.PSPath)`'; debug = `'$($result.debug)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/customErrors' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.3 Ensure custom error messages are not off";
        "Pass" = $(
            If (
                $result.mode -ne 'off'
            ){ $true } Else { $false });
        "Note" = "PSPath = `'$($result.PSPath)`'; mode = `'$($result.mode)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/httpErrors' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.4 Ensure IIS HTTP detailed errors are hidden from displaying remotely";
        "Pass" = $(
            If (
                $result.errorMode -in ('Custom','DetailedLocalOnly')
            ){ $true } Else { $false });
        "Note" = "PSPath = `'$($result.PSPath)`'; errorMode = `'$($result.errorMode)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/trace' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.5 Ensure ASP.NET stack tracing is not enabled";
        "Pass" = -not($result.enabled);
        "Note" = "PSPath = `'$($result.PSPath)`'; trace.enabled = `'$($result.enabled)`';";
    }
}

$results = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration().GetSection("system.web/trace")
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.5 Ensure ASP.NET stack tracing is not enabled";
        "Pass" = -not($result.enabled);
        "Note" = "PSPath = `'MACHINE/`'; trace.enabled = `'$($result.enabled)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/sessionState' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.6 Ensure 'httpcookie' mode is configured for session state";
        "WebSiteName"  = $PSItem.Name;
        "Pass" = $(
            if (
                $result.cookieless -in ("UseCookies","False")
            ) { $true } Else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; sessionState.cookieless = `'$($result.cookieless)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.web/httpCookies' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.7 Ensure 'cookies' are set with HttpOnly attribute";
        "Pass" = $result.httpOnlyCookies;
        "Note" = "PSPath = `'$($result.PSPath)`'; httpCookies.httpOnlyCookies = `'$($result.httpOnlyCookies)`';";
    }
}

Get-Website | Foreach-Object {
    $site = $PSItem
    $applicationPool = $PSItem.applicationPool
    If ($applicationPool) {
        $pools = Get-WebApplication -Site $PSItem.Name

        $pools | ForEach-Object {
            $appPool    = ($PSItem.Attributes | Where-Object Name -EQ 'applicationPool').Value
            $properties = Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *
            $version    = $properties.managedRuntimeVersion

            If ($version -Like "v2.*") {
                $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($site.Name)").Validation

                $raw += [PSCustomObject]@{
                    "ComputerName" = $cn;
                    "BenchMark" = $bm;
                    "Recommendation" = "3.8 Ensure 'MachineKey validation method - .Net 3.5' is configured";
                    "Pass" = [bool]$validation;
                    "Note" = "Site = `'$($site.name)`'; AppPoolName = `'$appPool`'; machineKey.Validation = $validation;"
                }
            }
        }
    }
}

Get-Website | Foreach-Object {
    $site = $PSItem
    $applicationPool = $PSItem.applicationPool
    If ($applicationPool) {
        $pools = Get-WebApplication -Site $PSItem.Name

        $pools | ForEach-Object {
            $appPool    = ($PSItem.Attributes | Where-Object Name -EQ 'applicationPool').Value
            $properties = Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *
            $version    = $properties.managedRuntimeVersion

            If ($version -Like "v4.*") {
                $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\Sites\$($site.Name)").Validation

                $raw += [PSCustomObject]@{
                    "ComputerName" = $cn;
                    "BenchMark" = $bm;
                    "Recommendation" = "3.9 Ensure 'MachineKey validation method - .Net 4.5' is configured";
                    "Pass" = [bool]$validation;
                    "Note" = "Site = `'$($site.name)`'; AppPoolName = `'$appPool`'; machineKey.Validation = $validation;"
                }
            }
        }
    }
}

Get-Website | Foreach-Object {
    $site = $PSItem
    $applicationPool = $PSItem.applicationPool
    If ($applicationPool) {
        $pools = Get-WebApplication -Site $PSItem.Name

        $pools | ForEach-Object {
            $appPool    = ($PSItem.Attributes | Where-Object Name -EQ 'applicationPool').Value
            $properties = Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *
            $version    = $properties.managedRuntimeVersion

            If ($version -Like "v2.*") {
                $level = (Get-WebConfiguration -Filter '/system.web/trust' -PSPath "IIS:\Sites\$($site.Name)").level

                $raw += [PSCustomObject]@{
                    "ComputerName" = $cn;
                    "BenchMark" = $bm;
                    "Recommendation" = "3.10 Ensure global .NET trust level is configured";
                    "Pass"   = $(
                        if (
                            $Level -in ("Medium","Low")
                        ) { $true } else { $false } 
                    );
                    "Note" = "Site = `'$($site.name)`'; AppPoolName = `'$appPool`'; trust.level = $Level;"
                }
            }
        }
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webserver/httpProtocol/customHeaders' -Recurse 
}
foreach ($result in $results) {
    foreach ($item in $result.GetCollection()) {
        if ($item.Attributes.value -match 'x-powered-by') {
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "3.11 Ensure X-Powered-By Header is removed";
                "Pass" = $false;
                "Note" = "PSPath = `'$($result.PSPath)`'; customHeaders.Attributes contains `'$($item.Attributes.value)`';";
            }
        }
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webserver/httpProtocol/customHeaders' -Recurse 
}
foreach ($result in $results) {
    foreach ($item in $result.GetCollection()) {
        if ($item.Attributes.value -match 'server') {
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "3.12 Ensure Server Header is removed";
                "Pass" = $false;
                "Note" = "PSPath = `'$($result.PSPath)`'; customHeaders.Attributes contains `'$($item.Attributes.value)`';";
            }
        }
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.requestLimits.Attributes | Where-Object -Property Name -eq 'maxAllowedContentLength'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.1 Ensure 'maxAllowedContentLength' is configured";
        "Pass" = [bool]$config.Value;
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.maxAllowedContentLength = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.requestLimits.Attributes | Where-Object -Property Name -eq 'maxURL'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.2 Ensure 'maxURL request filter' is configured";
        "Pass" = [bool]$config.Value;
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.maxURL = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.requestLimits.Attributes | Where-Object -Property Name -eq 'maxQueryString'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.3 Ensure 'MaxQueryString request filter' is configured";
        "Pass" = [bool]$config.Value;
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.maxQueryString = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.requestLimits.Attributes | Where-Object -Property Name -eq 'allowHighBitCharacters'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.4 Ensure non-ASCII characters in URLs are not allowed";
        "Pass" = -not([bool]$config.Value);
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.allowHighBitCharacters = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.requestLimits.Attributes | Where-Object -Property Name -eq 'allowDoubleEscaping'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.5 Ensure Double-Encoded requests will be rejected";
        "Pass" = -not([bool]$config.Value);
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.allowDoubleEscaping = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.verbs.Attributes | Where-Object -Property Name -eq 'trace'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.6 Ensure 'HTTP Trace Method' is disabled";
        "Pass" = -not([bool]$config.Value);
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.trace = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/requestFiltering' -Recurse 
}
foreach ($result in $results) {
    $config = $result.verbs.Attributes | Where-Object -Property Name -eq 'allowUnlisted'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.7 Ensure Unlisted File Extensions are not allowed";
        "Pass" = -not([bool]$config.Value);
        "Note" = "PSPath = `'$($result.PSPath)`'; requestFiltering.allowUnlisted = `'$($config.Value)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/handlers' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.8 Ensure Handler is not granted Write and Script/Execute";
        "Pass" = $(
            if (
                ($result.accessPolicy -notmatch 'Script' -or $result.accessPolicy -notmatch 'Execute')  -and 
                $result.accessPolicy -notmatch 'Write'
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; handlers.accessPolicy = `'$($result.accessPolicy)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/isapiCgiRestriction' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.9 Ensure 'notListedIsapisAllowed' is set to false";
        "Pass" = -not($result.notListedIsapisAllowed);
        "Note" = "PSPath = `'$($result.PSPath)`'; isapiCgiRestriction.notListedIsapisAllowed = `'$($result.notListedIsapisAllowed)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/isapiCgiRestriction' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.10 Ensure 'notListedCgisAllowed' is set to false";
        "Pass" = -not($result.notListedCgisAllowed);
        "Note" = "PSPath = `'$($result.PSPath)`'; isapiCgiRestriction.notListedCgisAllowed = `'$($result.notListedCgisAllowed)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/security/dynamicIpSecurity' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.11 Ensure 'Dynamic IP Address Restrictions' is enabled";
        "Pass" = $(
            if (
                [bool]$result.denyByConcurrentRequests.enabled -and
                [bool]$result.denyByRequestRate.enabled
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; dynamicIpSecurity.denyByConcurrentRequests = `'$($result.denyByConcurrentRequests.enabled)`'; dynamicIpSecurity.denyByRequestRate = `'$($result.denyByRequestRate.enabled)`';";
    }
}

$results = Get-Website 
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.11 Ensure 'Dynamic IP Address Restrictions' is enabled";
        "Pass" = $(
            if (
                $result.logFile.Directory -ne '%SystemDrive%\inetpub\logs\LogFiles'
            ) { $true } else { $false }
        );
        "Note" = "Site = `'$($result.Name)`'; logFile.Directory = `'$($result.logFile.Directory)`';";
    }
}

$results = Get-Website
foreach ($result in $results) {
    # https://forums.iis.net/t/1180288.aspx?Powershell%20environment%20variables%20issue=
    $logDirCount = (Get-ChildItem $($result.logFile.directory -replace "%SystemDrive%",$env:SystemDrive) -File -Recurse | Where-Object -Property LastWriteTime -GT (Get-Date).AddDays(-1)).count
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "5.2 Ensure Advanced IIS logging is enabled";
        "Pass" = $(
            if (
                $logDirCount -gt 0
            ) { $true } else { $false }
        );
        "Note" = "Site = `'$($result.Name)`'; logFile.directory.24hCount = `'$logDirCount`';";
    }
}

$results = Get-Website
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "5.3 Ensure 'ETW Logging' is enabled";
        "Pass" = $(
            if (
                $result.logFile.logTargetW3C -match 'File' -and
                $result.logFile.logTargetW3C -match 'ETW' 
            ) { $true } else { $false }
        );
        "Note" = "Site = `'$($result.Name)`'; logFile.logTargetW3C = `'$($result.logFile.logTargetW3C)`';";
    }
}


$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "6.1 Ensure FTP requests are encrypted";
        "Pass" = $(
            if (
                $result.controlChannelPolicy -eq 'SslRequire'-and
                $result.dataChannelPolicy -eq 'SslRequire'
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; ftpServer.controlChannelPolicy = `'$($result.controlChannelPolicy)`'; ftpServer.dataChannelPolicy = `'$($result.dataChannelPolicy)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.ftpServer/security/authentication' -Recurse 
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "6.2 Ensure FTP Logon attempt restrictions is enabled";
        "Pass" = $(
            if (
                [bool]$result.denyByFailure.enabled
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; ftpServer.denyByFailure = `'$([bool]$result.denyByFailure.enabled)`';";
    }
}

$results = Get-Website | %{
    Get-WebConfiguration -PSPath $PSItem.PSPath -filter 'system.webServer/httpProtocol' -Recurse 
}
foreach ($result in $results) {
    $value = ($result.customHeaders.Attributes | Where-Object Name -EQ 'Strict-Transport-Security').Value
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.1 Ensure HSTS Header is set";
        "Pass" = $(
            if (
                $value -gt 0
            ) { $true } else { $false }
        );
        "Note" = "PSPath = `'$($result.PSPath)`'; customHeaders.Strict-Transport-Security = `'$value`';";
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"
$expected = @{
    "Enabled" = 0;
    "DisabledByDefault" = 1;
}
$results = @()
foreach ($subpath in @("Client","Server")) {
    foreach ($key in $expected.Keys) {
        $pathsubpath = Join-Path $path -ChildPath $subpath
        $value = Get-ItemProperty $pathsubpath | Select-Object -ExpandProperty $key -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            "PSPath" = "$pathsubpath`:$key";
            "Value" = $value;
            "Pass" = [bool]($value -eq $expected[$key])
        }
    }
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.2 Ensure SSLv2 is Disabled";
        "Pass" = $result.Pass;
        "Note" = "PSPath = `'$($result.PSPath)`' = `'$($result.Value)`';";
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"
$expected = @{
    "Enabled" = 0;
    "DisabledByDefault" = 1;
}
$results = @()
foreach ($subpath in @("Client","Server")) {
    foreach ($key in $expected.Keys) {
        $pathsubpath = Join-Path $path -ChildPath $subpath
        $value = Get-ItemProperty $pathsubpath | Select-Object -ExpandProperty $key -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            "PSPath" = "$pathsubpath`:$key";
            "Value" = $value;
            "Pass" = [bool]($value -eq $expected[$key])
        }
    }
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.3 Ensure SSLv3 is Disabled";
        "Pass" = $result.Pass;
        "Note" = "PSPath = `'$($result.PSPath)`' = `'$($result.Value)`';";
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
$expected = @{
    "Enabled" = 0;
    "DisabledByDefault" = 1;
}
$results = @()
foreach ($subpath in @("Client","Server")) {
    foreach ($key in $expected.Keys) {
        $pathsubpath = Join-Path $path -ChildPath $subpath
        $value = Get-ItemProperty $pathsubpath | Select-Object -ExpandProperty $key
        $results += [PSCustomObject]@{
            "PSPath" = "$pathsubpath`:$key";
            "Value" = $value;
            "Pass" = [bool]($value -eq $expected[$key])
        }
    }
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.4 Ensure TLS 1.0 is Disabled";
        "Pass" = $result.Pass;
        "Note" = "PSPath = `'$($result.PSPath)`' = `'$($result.Value)`';";
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$expected = @{
    "Enabled" = 0;
    "DisabledByDefault" = 1;
}
$results = @()
foreach ($subpath in @("Client","Server")) {
    foreach ($key in $expected.Keys) {
        $pathsubpath = Join-Path $path -ChildPath $subpath
        $value = Get-ItemProperty $pathsubpath | Select-Object -ExpandProperty $key
        $results += [PSCustomObject]@{
            "PSPath" = "$pathsubpath`:$key";
            "Value" = $value;
            "Pass" = [bool]($value -eq $expected[$key])
        }
    }
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.5 Ensure TLS 1.1 is Disabled";
        "Pass" = $result.Pass;
        "Note" = "PSPath = `'$($result.PSPath)`' = `'$($result.Value)`';";
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
$expected = @{
    "Enabled" = 1;
    "DisabledByDefault" = 0;
}
$results = @()
foreach ($subpath in @("Server")) {
    foreach ($key in $expected.Keys) {
        $pathsubpath = Join-Path $path -ChildPath $subpath
        $value = Get-ItemProperty $pathsubpath | Select-Object -ExpandProperty $key
        $results += [PSCustomObject]@{
            "PSPath" = "$pathsubpath`:$key";
            "Value" = $value;
            "Pass" = [bool]($value -eq $expected[$key])
        }
    }
}
foreach ($result in $results) {
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.6 Ensure TLS 1.2 is Enabled";
        "Pass" = $result.Pass;
        "Note" = "PSPath = `'$($result.PSPath)`' = `'$($result.Value)`';";
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'
)
foreach ($key in $keys) {
    $result = Get-ItemProperty -Path $key -Name 'Enabled'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.7 Ensure NULL Cipher Suites is Disabled";
        "Pass"     = if ($result -eq 0) {$true} Else {$false};
        "Note" = "$key = `'$result`';";
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'
)
foreach ($key in $keys) {
    $result = Get-ItemProperty -Path $key -Name 'Enabled'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.8 Ensure DES Cipher Suites is Disabled";
        "Pass"     = if ($result -eq 0) {$true} Else {$false};
        "Note" = "$key = `'$result`';";
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
    ,'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
    ,'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
    ,'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
)
foreach ($key in $keys) {
    $result = Get-ItemProperty -Path $key -Name 'Enabled'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.9 Ensure RC4 Cipher Suites is Disabled";
        "Pass"     = if ($result -eq 0) {$true} Else {$false};
        "Note" = "$key = `'$result`';";
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
)
foreach ($key in $keys) {
    $result = Get-ItemProperty -Path $key -Name 'Enabled'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.10 Ensure AES 128/128 Cipher Suite is Disabled";
        "Pass"     = if ($result -eq 0) {$true} Else {$false};
        "Note" = "$key = `'$result`';";
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
)
foreach ($key in $keys) {
    $result = Get-ItemProperty -Path $key -Name 'Enabled'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.11 Ensure AES 256/256 Cipher Suite is Enabled";
        "Pass"     = if ($value -eq 1) {$true} Else {$false};
        "Note" = "$key = `'$result`';";
    }
}

$keys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
)
$xp = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
foreach ($key in $keys) {
    $result = Get-ItemProperty -Path $key -Name 'Functions'
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.12 Ensure TLS Cipher Suite ordering is Configured";
        "Pass"     = if ($value -eq $xp) {$true} Else {$false};
        "Note" = "$key = `'$result`';";
    }
}

return $raw