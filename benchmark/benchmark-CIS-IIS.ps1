<#
.SYNOPSIS
    invokeBenchMark-CIS-IIS
.DESCRIPTION
    1. This script copied to server by invokeBenchMark.ps1
    2. Run benchmark and return results as PSCustomObject
.NOTES
    Author:  ts-systech-team@scu.edu.au
    Created: 27-Sep-2021
    LastMod: 28-Oct-2021 - use $raw
.REFERENCE
    https://www.cisecurity.org/cis-benchmarks/
#>

$raw = @()
$cn = $env:COMPUTERNAME
$bm = "CIS_IIS10_v1.1.1"

$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "1.1 Ensure web content is on non-system partition";
    "Pass" = $(
        $test = Get-Content (Join-Path -Path $Env:SystemRoot -ChildPath 'System32\inetsrv\config\applicationHost.config')
        If (
            (Test-Path -Path (Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub')) -And
            $test -Match [RegEx]::Escape((Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub'))
        ) {
            $true
        } Else {
            $false
        }
    );
}

Get-Website | ForEach-Object {
    $noHostHeader = (Get-WebBinding -Port *).bindingInformation | ForEach-Object {
        $PSItem | Select-String -Pattern ".+\:80\:$"
    }

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.2 Ensure 'host headers' are on all sites ";
        "WebSiteName" = $PSItem.Name;
        "Pass" = -not([bool]$noHostHeader);
    } 
}

Get-Website | ForEach-Object {
    $dirbrowse = (Get-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -PSPath "IIS:\Sites\$($PSItem.Name)" -Name "enabled").Value;

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.3 Ensure 'directory browsing' is set to disabled";
        "WebSiteName" = $PSItem.Name;
        "directoryBrowse" = $dirbrowse;
        "Pass" = -not($dirbrowse);
    } 
}

Get-ChildItem 'IIS:\AppPools' | ForEach-Object {
    $processModels = Get-ItemProperty "IIS:\AppPools\$($PSItem.Name)" | Select-Object -ExpandProperty 'processModel'

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.4 Ensure 'application pool identity' is configured for all application pools";
        "AppPoolName" = $PSItem.Name;
        "AppPoolIdentityType" = $PSItem.processModel.identityType;
        "AppPoolUserName" = $PSItem.processModel.userName;
        "Pass" = $(
            If ( $processModels.identityType -NE 'ApplicationPoolIdentity' ) {
                $false
            } Else {
                $true
            }
        )
    }
}

Get-WebApplication | Group-Object -Property 'applicationPool' | 
    Select-Object Count, Name |
    Sort-Object Name | 
    ForEach-Object {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "1.5 Ensure 'unique application pools' is set for sites";
            "AppPoolName" = $PSItem.Name;
            "Pass" = $($PSItem.count -eq 1);
        }
    }

Get-ChildItem 'IIS:\Sites' | Foreach-Object {
    $anonAuth = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -PSPath "IIS:\Sites\$($PSItem.Name)" -Name "userName").Value
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "1.6 Ensure ‘application pool identity’ is configured for anonymous user identity";
        "WebsiteName" = $PSItem.Name;
        "Pass" = $(If($anonAuth -EQ '') {$false}Else{$true});
    }
}

$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "1.7 Ensure WebDav feature is disabled";
    "Pass" = $([Bool](Get-WindowsFeature -Name 'Web-DAV-Publishing' | Where-Object Installed -EQ $false));
}

if ((Get-WindowsFeature Web-Url-Auth).Installed -EQ $true) {
  Get-WebSite | ForEach-Object {
    $site = $PSItem.Name
    $config = Get-WebConfiguration -Filter "system.webServer/security/authorization" -PSPath "IIS:\Sites\$($PSItem.Name)"

    $config.GetCollection() | ForEach-Object {
        $accessType = ($PSItem.Attributes | Where-Object Name -EQ 'accessType').Value
        $users = ($PSItem.Attributes | Where-Object Name -EQ 'users').Value
        $roles = ($PSItem.Attributes | Where-Object Name -EQ 'roles').Value

        If (($accessType -eq "Allow" -or $accessType -eq 0) -And ($users -eq "*" -or $roles -eq "?")) {
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "2.1 Ensure 'global authorization rule' is set to restrict access";
                "WebsiteName" = $site;
                "AccessType" = $accessType;
                "Users" = $users;
                "Roles" = $roles;
                "Pass" = $false;
            }
        } Else {
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "2.1 Ensure 'global authorization rule' is set to restrict access";
                "WebsiteName" = $site;
                "AccessType" = $accessType;
                "Users" = $users;
                "Roles" = $roles;
                "Pass" = $true;
            }
        }
    }
  }
}

Get-Website | Foreach-Object {
    $mode = (Get-WebConfiguration -Filter 'system.web/authentication' -PSPath "IIS:\sites\$($PSItem.Name)").mode
  
    If (($mode -NE 'forms') -And ($mode -NE 'Windows')) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.2 Ensure access to sensitive site features is restricted to authenticated principals only";
            "WebsiteName" = $PSItem.Name;
            "Pass" = $false;
        }
    } Else {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.2 Ensure access to sensitive site features is restricted to authenticated principals only";
            "WebsiteName" = $PSItem.Name;
            "Pass" = $true;
        }
    }
}

Get-Website | Foreach-Object {
    $config = (Get-WebConfiguration -Filter 'system.web/authentication' -PSPath "IIS:\sites\$($PSItem.Name)")

    If ($config.mode -EQ 'forms') {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.3 Ensure ‘forms authentication’ requires SSL";
            "WebsiteName" = $PSItem.Name;
            "Pass"  = $config.Forms.RequireSSL;
        }
    }
}

Get-Website | Foreach-Object {
    $config = (Get-WebConfiguration -Filter '/system.web/authentication' -PSPath "IIS:\sites\$($PSItem.Name)")

    If ($config.mode -EQ 'forms') {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.4 Ensure ‘forms authentication’ is set to use cookies";
            "Pass" = $(If($config.Forms.Cookieless -NE 'UseCookie') { $false } Else { $true });
        }
    }
}

Get-Website | Foreach-Object {
    $config = (Get-WebConfiguration -Filter '/system.web/authentication' -PSPath "IIS:\sites\$($PSItem.Name)")

    If ($config.mode -EQ 'forms') {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.5 Ensure ‘cookie protection mode’ is configured for forms authentication";
            "Pass" = $(If($config.Forms.protection -NE 'All') { $false } Else { $true })
        }
    }
}

Get-Website | Foreach-Object {
      $ssl   = (Get-WebConfiguration -Filter "/system.webServer/security/access" -PSPath "IIS:\sites\$($PSItem.Name)").SSLFlags
      $basic = (Get-WebConfigurationProperty -filter "/system.WebServer/security/authentication/basicAuthentication" -name Enabled -PSPath "IIS:\sites\$($PSItem.Name)").Value

      If ($basic) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.6 Ensure transport layer security for ‘basic authentication’ is configured";
            "Pass"  = $(If($ssl -EQ 'Ssl') { $true } Else { $false });
        }
    }
}

# Individual site config
Get-Website | Foreach-Object {
    $config = (Get-WebConfiguration -Filter '/system.web/authentication' -PSPath "IIS:\sites\$($PSItem.Name)")
    $format = (Get-WebConfiguration -Filter '/system.web/authentication/forms/credentials' -PSPath "IIS:\sites\$($PSItem.Name)").passwordFormat

    if ($config.mode -EQ 'forms') {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.7 Ensure 'passwordFormat' is not set to clear";
            "WebSiteName" = $PSItem.Name;
            "Pass" = $(if($format -EQ 'clear'){ $false } Else { $true });
        }
    }
}

# Machine Config
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$passwordFormat = $machineConfig.GetSection("system.web/authentication").forms.credentials.passwordFormat
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "2.7 Ensure 'passwordFormat' is not set to clear";
        "WebSiteName" = "MachineConfiguration";
        "Pass" = $(if($passwordFormat -EQ 'clear'){ $false } Else { $true });
    }

Get-Website | Foreach-Object {
    $config = (Get-WebConfiguration -Filter '/system.web/authentication' -PSPath "IIS:\sites\$($PSItem.Name)")
    $stored = (Get-WebConfiguration -filter '/system.web/authentication/forms/credentials' -PSPath "IIS:\sites\$($PSItem.Name)").IsLocallyStored

    If ($config.mode -EQ 'forms') {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "2.8 Ensure 'credentials' are not stored in configuration files";
            "WebSiteName" = $PSItem.Name;
            "Pass" = -not($stored);
        }
    }
}

$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$deployment = $machineConfig.GetSection("system.web/deployment")
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.1 Ensure 'deployment method retail' is set";
        "Pass" = $deployment.Retail;
    }

Get-Website | Foreach-Object {
    $debug = (Get-WebConfiguration -Filter '/system.web/compilation' -PSPath "IIS:\sites\$($PSItem.Name)").Debug
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.2 Ensure 'debug' is turned off";
        "WebSiteName"  = $PSItem.Name;
        "Pass" = -not($debug);
    }
}

Get-Website | Foreach-Object {
    $mode = (Get-WebConfiguration -Filter '/system.web/customErrors' -PSPath "IIS:\sites\$($PSItem.Name)").Mode

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.3 Ensure custom error messages are not off";
        "WebSiteName"  = $PSItem.Name;
        "Mode"  = $mode;
        "Pass" = $(If($mode -EQ 'off'){$false}Else{$true});
    }
}

Get-Website | Foreach-Object {
    $errorMode = (Get-WebConfiguration -Filter '/system.webServer/httpErrors' -PSPath "IIS:\sites\$($_.Name)").errorMode

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.4 Ensure IIS HTTP detailed errors are hidden from displaying remotely";
        "WebSiteName"  = $PSItem.Name;
        "ErrorMode" = $errorMode;
        "Pass" = $(If(($errorMode -notin ('Custom','DetailedLocalOnly'))){ $False } Else { $True });
    }
}

# Individual Site Config
Get-Website | Foreach-Object {
    $trace = (Get-WebConfiguration -Filter '/system.web/trace' -PSPath "IIS:\sites\$($PSItem.Name)").enabled
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.5 Ensure ASP.NET stack tracing is not enabled";
        "WebSiteName"  = $PSItem.Name;
        "Pass" = -not($trace);
    }
}

# Machine Config
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$deployment = $machineConfig.GetSection("system.web/trace")
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.5 Ensure ASP.NET stack tracing is not enabled";
        "WebSiteName"  = "MachineConfiguration";
        "Pass" = -not($deployment.enabled);
    }

Get-Website | Foreach-Object {
    $sessionState = (Get-WebConfiguration -Filter '/system.web/sessionState' -PSPath "IIS:\sites\$($PSItem.Name)").cookieless

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.6 Ensure 'httpcookie' mode is configured for session state";
        "WebSiteName"  = $PSItem.Name;
        "Pass" = $(If(($sessionState -notin ("UseCookies","False"))) { $false } Else { $true })
    }
}

Get-Website | Foreach-Object {
    $httpCookies = (Get-WebConfiguration -Filter '/system.web/httpCookies' -PSPath "IIS:\sites\$($PSItem.Name)").httpOnlyCookies
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "3.7 Ensure 'cookies' are set with HttpOnly attribute";
        "WebSiteName"  = $PSItem.Name;
        "Pass" = $httpCookies;
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
                    "Recommendation" = "3.8 Ensure 'cookies' are set with HttpOnly attribute";
                    "WebSiteName"  = $site.Name;
                    "AppPoolName"    = $appPool;
                    "Version"    = $version;
                    "Pass" = [bool]$validation;
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
                $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$($site.Name)").Validation

                $raw += [PSCustomObject]@{
                    "ComputerName" = $cn;
                    "BenchMark" = $bm;
                    "Recommendation" = "3.9 Ensure 'MachineKey validation method - .Net 4.5' is configured";
                    "WebSiteName"  = $site.Name;
                    "AppPoolName"    = $appPool;
                    "Version"    = $version;
                    "Pass" = [bool]$validation;
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

            $level = (Get-WebConfiguration -Filter '/system.web/trust' -PSPath "IIS:\sites\$($site.Name)").level

            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "3.10 Ensure global .NET trust level is configured";
                "WebSiteName"  = $site.Name;
                "AppPoolName" = $appPool;
                "Version" = $version;
                "Pass"   = if ($Level -in ("Medium","Low")){ $true } else { $false } ;

            }
        }
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$($site.Name)"

    $customHeaders = $config.GetCollection()

    If ($customHeaders) {
        $customHeaders | ForEach-Object {
            $xpoweredby = ($_.Attributes | Where-Object Name -EQ name).Value -match 'x-powered-by'
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "3.11 Ensure X-Powered-By Header is removed";
                "WebSiteName"  = $site.Name;
                "Pass" = -not($xpoweredby);
            }
        }
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$($site.Name)"

    $customHeaders = $config.GetCollection()

    If ($customHeaders) {
        $customHeaders | ForEach-Object {
            $xserver = ($_.Attributes | Where-Object Name -EQ name).Value -match 'server'
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "3.12 Ensure Server Header is removed";
                "WebSiteName"  = $site.Name;
                "Pass" = -not($xserver);
            }
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $maxAllowedContentLength = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").requestLimits).Attributes | Where-Object Name -EQ 'maxAllowedContentLength').Value
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.1 Ensure 'maxAllowedContentLength' is configured";
            "WebSiteName"  = $site.Name;
            "Pass" = [bool]$maxAllowedContentLength;
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $maxUrl = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").requestLimits).Attributes | Where-Object Name -EQ 'maxURL').Value
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.2 Ensure 'maxURL request filter' is configured";
            "WebSiteName"  = $site.Name;
            "Pass" = [bool]$maxUrl
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $maxQueryString = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").requestLimits).Attributes | Where-Object Name -EQ 'maxQueryString').Value
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.3 Ensure 'MaxQueryString request filter' is configured";
            "WebSiteName"  = $site.Name;
            "Pass" = [bool]$maxQueryString;
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $allowHighBitCharacters = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").allowHighBitCharacters
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.4 Ensure non-ASCII characters in URLs are not allowed";
            "WebSiteName"  = $site.Name;
            "Pass" = -not($allowHighBitCharacters);
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $allowDoubleEscaping = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").allowDoubleEscaping
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.5 Ensure Double-Encoded requests will be rejected";
            "WebSiteName"  = $site.Name;
            "Pass" = -not($allowDoubleEscaping);
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_

        $config = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)")

        $trace = $config.verbs.Attributes | Where-Object {
            $_.Name -EQ 'trace'
        }

        if ([bool]$trace) {
            $raw += [PSCustomObject]@{
                "ComputerName" = $cn;
                "BenchMark" = $bm;
                "Recommendation" = "4.6 Ensure 'HTTP Trace Method' is disabled";
                "WebSiteName"  = $site.Name;
                "Pass" = -not($trace);
            }
        }
    }
}

If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $allowUnlisted = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$($site.Name)").fileExtensions).Attributes | Where-Object Name -EQ 'allowUnlisted').Value
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.7 Ensure Unlisted File Extensions are not allowed";
            "WebSiteName"  = $site.Name;
            "Pass" = -not($allowUnlisted);
        }
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $accessPolicy = (Get-WebConfiguration -Filter 'system.webServer/handlers' -PSPath "IIS:\sites\$($site.Name)").accessPolicy
    $accessPolicyWrite = [bool]($accessPolicy  | Select-String -Pattern 'Script|Execute' | Select-String -Pattern 'Write')
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.8 Ensure Handler is not granted Write and Script/Execute";
        "WebSiteName"  = $site.Name;
        "Pass" = -not($accessPolicyWrite);
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $notListedIsapisAllowed = (Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$($site.Name)").notListedIsapisAllowed
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.9 Ensure 'notListedIsapisAllowed' is set to false";
        "WebSiteName"  = $site.Name;
        "Pass" = -not($notListedIsapisAllowed);
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $notListedCgisAllowed = (Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$($site.Name)").notListedCgisAllowed
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "4.10 Ensure 'notListedCgisAllowed' is set to false";
        "WebSiteName"  = $site.Name;
        "Pass" = -not($notListedCgisAllowed);
    }
}

If ((Get-WindowsFeature Web-Ip-Security).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $config = Get-WebConfiguration -Filter '/system.webServer/security/dynamicIpSecurity' -PSPath "IIS:\sites\$($site.Name)"
        $denyByConcurrentRequests = $config.denyByConcurrentRequests.enabled
        $denyByRequestRate = $config.denyByRequestRate.enabled
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "4.11 Ensure 'Dynamic IP Address Restrictions' is enabled";
            "WebSiteName"  = $site.Name;
            "Pass" = ([bool]$denyByRequestRate -and [bool]$denyByConcurrentRequests);
        }
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $Location = $Site.logFile.Directory
    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "5.1 Ensure Default IIS web log location is moved";
        "WebSiteName"  = $site.Name;
        "Pass" = ($Location -ne "%SystemDrive%\inetpub\logs\LogFiles")
    }
}

# 5.2 Ensure Advanced IIS logging is enabled; IIS 10 default = enabled

Get-Website | Foreach-Object {
    $site = $_
    $logTargetW3C = $Site.logFile.logTargetW3C
    $logFileETW = $logTargetW3C | Select-String -Pattern 'File' | Select-String -Pattern 'ETW'

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "5.3 Ensure 'ETW Logging' is enabled";
        "WebSiteName"  = $site.Name;
        "Pass" = [bool]$logFileETW;
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $FTPBindings = $site.bindings.collection | Where-Object -Property Protocol -eq FTP
    If ($FTPBindings) {
        $config = (Get-WebConfiguration -Filter 'system.applicationHost/sites' -PSPath "IIS:\sites\$($site.Name)").siteDefaults.ftpServer.security.ssl

        #($config.Attributes | Where-Object Name -EQ 'controlChannelPolicy').Value
        #($config.Attributes | Where-Object Name -EQ 'dataChannelPolicy').Value

        $result = if ($config.controlChannelPolicy -eq 'SslRequire' -and $config.dataChannelPolicy -eq 'SslRequire') {$true} else {$false}
        
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "6.1 Ensure FTP requests are encrypted";
            "WebSiteName"  = $site.Name;
            "Pass" = [bool]$result;
        }
    }
}

Get-Website | Foreach-Object {
    $site = $_
    $FTPBindings = $site.bindings.collection | Where-Object -Property 'Protocol' -eq 'FTP'
    if ($FTPBindings) {
        $config = (Get-WebConfiguration -Filter 'system.ftpServer/security/authentication' -PSPath "IIS:\sites\$($site.Name)").denyByFailure
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "6.2 Ensure FTP Logon attempt restrictions is enabled";
            "WebSiteName"  = $site.Name;
            "Pass"     = $config.enabled;
        }
    }
}

Get-Website | Foreach-Object {
    $site   = $_
    $config = (Get-WebConfiguration -Filter '/system.webServer/httpProtocol' -PSPath "IIS:\sites\$($site.Name)").customHeaders
    $value  = ($config.Attributes | Where-Object Name -EQ 'Strict-Transport-Security').Value

    $maxage = $value | Where-Object { $_ -Match "max-age" }

    $raw += [PSCustomObject]@{
        "ComputerName" = $cn;
        "BenchMark" = $bm;
        "Recommendation" = "7.1 Ensure HSTS Header is set";
        "WebSiteName"  = $site.Name;
        "max-age" = $maxage;
        "Pass"     = if($maxage -gt 0) {$true} else {$false}
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"
If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.2 Ensure SSLv2 is Disabled";
            "Pass"     = if ($value -ne 0) {$false} Else {$true}
        }
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"
If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.3 Ensure SSLv3 is Disabled";
            "Pass"     = if ($value -ne 0) {$false} Else {$true}
        }
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.4 Ensure TLS 1.0 is Disabled";
            "Pass"     = if ($value -ne 0) {$false} Else {$true}
        }
    }
}

$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.5 Ensure TLS 1.1 is Disabled";
            "Pass"     = if ($value -ne 0) {$false} Else {$true}
        }
    }
}


$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is not set to 0
        
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.6 Ensure TLS 1.2 is Enabled";
            "Pass"     = if ($value -eq 0) {$false} Else {$true}
        }
    }
}

$value = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -name 'Enabled'
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "7.7 Ensure NULL Cipher Suites is Disabled";
    "Pass"     = if ($value -eq 0) {$true} Else {$false}
}

$value = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -name 'Enabled'
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "7.8 Ensure DES Cipher Suites is Disabled";
    "Pass"     = if ($value -eq 0) {$true} Else {$false}
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
    ,'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
    ,'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
    ,'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
)
foreach ($key in $keys) {
    try {
        $value = Get-ItemProperty -path $key -name 'Enabled'
    } catch {}
    if ([bool]$value) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.9 Ensure RC4 Cipher Suites is Disabled $key";
            "Pass"     = if ($value -eq 0) {$true} Else {$false}
        }
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
)
foreach ($key in $keys) {
    try {
        $value = Get-ItemProperty -path $key -name 'Enabled'
    } catch {}
    if ([bool]$value) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.10 Ensure AES 128/128 Cipher Suite is Disabled $key";
            "Pass"     = if ($value -eq 0) {$true} Else {$false}
        }
    }
}

$keys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
)
foreach ($key in $keys) {
    try {
        $value = Get-ItemProperty -path $key -name 'Enabled'
    } catch {}
    if ([bool]$value) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.11 Ensure AES 256/256 Cipher Suite is Enabled $key";
            "Pass"     = if ($value -eq 1) {$true} Else {$false}
        }
    }
}

$keys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
)
$xp = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
foreach ($key in $keys) {
    try {
        $value = Get-ItemProperty -path $key -name 'Functions'
    } catch {}
    if ([bool]$value) {
        $raw += [PSCustomObject]@{
            "ComputerName" = $cn;
            "BenchMark" = $bm;
            "Recommendation" = "7.12 Ensure TLS Cipher Suite ordering is Configured";
            "Pass"     = if ($value -eq $xp) {$true} Else {$false}
        }
    }
}

return $raw