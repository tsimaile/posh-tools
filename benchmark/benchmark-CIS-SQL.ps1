<#
.SYNOPSIS
    invokeBenchMark-CIS-SQL
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
$bm = "CIS_SQL_2019_1.2.0"

# https://docs.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server?view=sql-server-ver15
# https://sqlserverbuilds.blogspot.com/
$expect = @{
    "15" = [PSCustomObject]@{
        "Version" = "15.0.4178.1";
        "SP" = "RTM";
        "CU" = "CU13";
    };
    "14" = [PSCustomObject]@{
        "Version" = "14.0.3411.3";
        "SP" = "RTM";
        "CU" = "CU26";
    };
    "13" = [PSCustomObject]@{
        "Version" = "13.3.6300.2";
        "SP" = "SP3";
        "CU" = "CU17";
    };
    "12" = [PSCustomObject]@{
        "Version" = "12.3.6024.0";
        "SP" = "SP3";
        "CU" = "CU4";
    };
    "11" = [PSCustomObject]@{
        "Version" = "11.4.7001.0";
        "SP" = "SP4";
        "CU" = "CU10";
    };
}

$script = @"
SELECT        SERVERPROPERTY('ProductMajorVersion') AS MajorVersion, SERVERPROPERTY('ProductVersion') AS Version, SERVERPROPERTY('ProductLevel') AS SP, SERVERPROPERTY('ProductUpdateLevel') AS CU
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "1.1 Ensure Latest SQL Server Cumulative and Security Updates are Installed";
    "Version" = $result.Version;
    "SP" = $result.SP;
    "CU" = $result.CU;
    "Pass" = $(
        if (
            $result.Version -eq $expect[$result.MajorVersion].Version -and
            $result.SP -eq $expect[$result.MajorVersion].SP -and
            $result.CU -eq $expect[$result.MajorVersion].CU
        ) { $true } else { $false }
    );
    "Note" = "$($result.Version) // $($expect[$result.MajorVersion].Version)";
}

$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "1.2 Ensure Single-Function Member Servers are Used";
    "Pass" = $true;
    "Note" = "SQL architecture prefers dedicated server";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'Ad Hoc Distributed Queries')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    SELECT        DB_NAME() AS database_name, name AS Assembly_Name, permission_set_desc
    FROM            sys.assemblies
    WHERE        (is_user_defined = 1) AND (permission_set_desc <> ''SAFE'')
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = "CLR Enabled count = $($result.count)";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'cross db ownership chaining')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'Database Mail XPs')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'Ole Automation Procedures')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'remote access')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.6 Ensure 'Remote Access' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
USE master;
GO
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'remote admin connections') AND (SERVERPROPERTY('IsClustered') = 0)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'scan for startup procs')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'";
    "Pass" = $(
        if (
            $result.value_configured -eq 0 -and
            $result.value_in_use -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use);";
}

$script = @"
SELECT        COUNT(name) AS trustworthyCountName
FROM            sys.databases
WHERE        (is_trustworthy_on = 1) AND (name <> 'msdb')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.9 Ensure 'Trustworthy' Database Property is set to 'Off'";
    "Pass" = $(
        if (
            $result.trustworthyCountName -eq 0 
        ) { $true } else { $false }
    );
    "Note" = "Trustworthy count = $($result.trustworthyCountName);";
}

# https://www.mssqltips.com/sqlservertip/5626/determine-sql-server-network-protocol-information-using-tsql-and-dmvs/
$script = @"
SELECT        registry_key, value_name, value_data
FROM            sys.dm_server_registry
WHERE        (registry_key LIKE '%SuperSocketNetLib%') AND (value_name = 'Enabled') AND (value_data = 1)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled'";
    "Pass" = $(
        if (
            $result.count -eq 2 -and
            'HKLM\Software\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Sm' -in $result.registry_key -and
            'HKLM\Software\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Tcp' -in $result.registry_key
        ) { $true } else { $false }
    );
    "Note" = "SM = $(($result | Where-Object -Property registry_key -EQ 'HKLM\Software\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Sm').value_name); TCP = $(($result | Where-Object -Property registry_key -EQ 'HKLM\Software\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib\Tcp').value_name);";
}

$script = @"
SELECT        TOP (1) local_tcp_port
FROM            sys.dm_exec_connections
WHERE        (local_tcp_port IS NOT NULL)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.11 Ensure SQL Server is configured to use non-standard ports";
    "Pass" = $(
        if (
            $result.local_tcp_port -ne 1433
        ) { $true } else { $false }
    );
    "Note" = "local_tcp_port = $($result.local_tcp_port);"
}

$script = @"
DECLARE @getValue INT;
EXEC master.sys.xp_instance_regread
@rootkey = N'HKEY_LOCAL_MACHINE',
@key = N'SOFTWARE\Microsoft\Microsoft SQL
Server\MSSQLServer\SuperSocketNetLib',
@value_name = N'HideInstance',
@value = @getValue OUTPUT;
SELECT @getValue AS value_data;
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances";
    "Pass" = $(
        if (
            $result.value_data -eq 1
        ) { $true } else { $false }
    );
    "Note" = "value_data = $($result.value_data);"
}

$script = @"
SELECT        COUNT(*) AS value_count
FROM            sys.server_principals
WHERE        (sid = 0x01) AND (is_disabled = 0)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.13 Ensure the 'sa' Login Account is set to 'Disabled'";
    "Pass" = $(
        if (
            $result.value_count -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_count = $($result.value_count);"
}

$script = @"
SELECT        name, is_disabled
FROM            sys.server_principals
WHERE        (sid = 0x01)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.14 Ensure the 'sa' Login Account has been renamed";
    "Pass" = $(
        if (
            #$result.is_disabled -eq 1 -or 
            'sa' -notin $result.name
        ) { $true } else { $false }
    );
    #"Note" = "";
}

$script = @"
SELECT        COUNT(*) AS value_count
FROM            sys.databases
WHERE        (containment <> 0) AND (is_auto_close_on = 1)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.15 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases";
    "Pass" = $(
        if (
            $result.value_count -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_count = $($result.value_count);";
}

$script = @"
SELECT        COUNT(*) AS value_count
FROM            sys.server_principals
WHERE        (name = 'sa')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.16 Ensure no login exists with the name 'sa'";
    "Pass" = $(
        if (
            $result.value_count -eq 0
        ) { $true } else { $false }
    );
    "Note" = "value_count = $($result.value_count);";
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    SELECT DB_NAME() as database_name, name AS Assembly_Name, permission_set_desc
    FROM sys.assemblies
    WHERE is_user_defined = 1;
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "2.17 Ensure 'clr strict security' Server Configuration Option is set to '1'";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = "is_user_defined count = $($result.count);";
}

$script = @"
SELECT        SERVERPROPERTY('IsIntegratedSecurityOnly') AS login_mode
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'";
    "Pass" = $(
        if (
            $result.login_mode -eq 1
        ) { $true } else { $false }
    );
    "Note" = "login_mode = $($result.login_mode);";
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    SELECT DB_NAME() AS DatabaseName, ''guest'' AS Database_User,
    [permission_name], [state_desc]
    FROM sys.database_permissions
    WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID(''guest'')
    AND [state_desc] LIKE ''GRANT%''
    AND [permission_name] = ''CONNECT''
    AND DB_NAME() NOT IN (''master'',''tempdb'',''msdb'');
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases excluding the master, msdb and tempdb";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    #"Note" = "guest count = $($result.count);";
}

# VARIATION: http://dbadiaries.com/using-sp_change_users_login-to-fix-sql-server-orphaned-users
$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    --SELECT        DB_NAME() AS database_name, dp.type_desc, dp.sid, dp.name AS user_name
    --FROM            sys.database_principals AS dp LEFT OUTER JOIN
    --                         sys.server_principals AS sp ON dp.sid = sp.sid
    --WHERE        (sp.sid IS NULL) AND (dp.authentication_type_desc = ''INSTANCE'')
    EXEC sp_change_users_login @Action=''Report'';
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = "orphan count = $($result.count);";
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
	SELECT DB_NAME() AS database_name, name AS DBUser
	FROM sys.database_principals
	WHERE name NOT IN (''dbo'',''Information_Schema'',''sys'',''guest'')
	AND type IN (''U'',''S'',''G'')
	AND authentication_type = 2;
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.4 Ensure SQL Authentication is not used in contained databases";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = "DBUser count = $($result.count);";
}

$result = $true
$note = ""
$localAdmins = Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue
if ($localAdmins -eq $null) { 
    $result = $false 
    $note = "ERROR: unable to resolve all local admins"
} else {
    $services = Get-CimInstance -Class Win32_Service | 
        Where-Object -Property Name -LIKE 'MSSQL*' | 
        Select-Object Name, StartName

    foreach ($service in $services) {
        if ($service.StartName -in $localAdmins.Name) {
            $result = $false
            $note = "$($service.Name) = $($service.StartName)"
        }
    }
}
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.5 Ensure the SQL Server’s MSSQL Service Account is Not an Administrator";
    "Pass" = $result;
    "Note" = $note;
}

$result = $true
$note = ""
$localAdmins = Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue
if ($localAdmins -eq $null) { 
    $result = $false 
    $note = "ERROR: unable to resolve all local admins"
} else {
    $services = Get-CimInstance -Class Win32_Service | 
        Where-Object -Property Name -LIKE 'SQL*AGENT*' | 
        Select-Object Name, StartName

    foreach ($service in $services) {
        if ($service.StartName -in $localAdmins.Name) {
            $result = $false
            $note = "$($service.Name) = $($service.StartName)"
        }
    }
}
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.6 Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator";
    "Pass" = $result;
    "Note" = $note;
}

$result = $true
$note = ""
$localAdmins = Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue
if ($localAdmins -eq $null) { 
    $result = $false 
    $note = "ERROR: unable to resolve all local admins"
} else {
    $services = Get-CimInstance -Class Win32_Service | 
        Where-Object -Property Name -LIKE 'MSSQLFDLauncher*' | 
        Select-Object Name, StartName

    foreach ($service in $services) {
        if ($service.StartName -in $localAdmins.Name) {
            $result = $false
            $note = "$($service.Name) = $($service.StartName)"
        }
    }
}
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.7 Ensure the SQL Server’s Full-Text Service Account is Not an Administrator";
    "Pass" = $result;
    "Note" = $note;
}

$script = @"
SELECT        class, class_desc, major_id, minor_id, grantee_principal_id, grantor_principal_id, type, permission_name, state, state_desc
FROM            master.sys.server_permissions
WHERE        (grantee_principal_id = SUSER_SID(N'public')) AND (state_desc LIKE 'GRANT%') AND (NOT (state_desc = 'GRANT') OR
                         NOT (permission_name = 'VIEW ANY DATABASE') OR
                         NOT (class_desc = 'SERVER')) AND (NOT (state_desc = 'GRANT') OR
                         NOT (permission_name = 'CONNECT') OR
                         NOT (class_desc = 'ENDPOINT') OR
                         NOT (major_id = 2)) AND (NOT (state_desc = 'GRANT') OR
                         NOT (permission_name = 'CONNECT') OR
                         NOT (class_desc = 'ENDPOINT') OR
                         NOT (major_id = 3)) AND (NOT (state_desc = 'GRANT') OR
                         NOT (permission_name = 'CONNECT') OR
                         NOT (class_desc = 'ENDPOINT') OR
                         NOT (major_id = 4)) AND (NOT (state_desc = 'GRANT') OR
                         NOT (permission_name = 'CONNECT') OR
                         NOT (class_desc = 'ENDPOINT') OR
                         NOT (major_id = 5))
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
}

$script = @"
SELECT        pr.name, pe.permission_name, pe.state_desc
FROM            sys.server_principals AS pr INNER JOIN
                         sys.server_permissions AS pe ON pr.principal_id = pe.grantee_principal_id
WHERE        (pr.name LIKE 'BUILTIN%')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.9 Ensure Windows BUILTIN groups are not SQL Logins";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
}

$script = @"
USE [master]
GO
SELECT        pr.name AS LocalGroupName, pe.permission_name, pe.state_desc
FROM            sys.server_principals AS pr INNER JOIN
                         sys.server_permissions AS pe ON pr.principal_id = pe.grantee_principal_id
WHERE        (pr.type_desc = 'WINDOWS_GROUP') AND (pr.name LIKE CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.10 Ensure Windows local groups are not SQL Logins";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
}

$script = @"
USE [msdb]
GO
SELECT        sp.name AS proxyname
FROM            sysproxylogin AS spl INNER JOIN
                         sys.database_principals AS dp ON dp.sid = spl.sid INNER JOIN
                         sysproxies AS sp ON sp.proxy_id = spl.proxy_id
WHERE        (dp.principal_id = USER_ID('public'))
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
}

# 4.1

$script = @"
SELECT        name, 'sysadmin membership' AS 'Access_Method'
FROM            sys.sql_logins AS l
WHERE        (IS_SRVROLEMEMBER('sysadmin', name) = 1) AND (is_expiration_checked <> 1) AND (is_disabled = 0)
UNION ALL
SELECT        l.name, 'CONTROL SERVER' AS 'Access_Method'
FROM            sys.sql_logins AS l INNER JOIN
                         sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id
WHERE        (p.type = 'CL') AND (p.state IN ('G', 'W')) AND (l.is_expiration_checked <> 1) AND (l.is_disabled = 0)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
}

$script = @"
SELECT        name, is_disabled
FROM            sys.sql_logins
WHERE        (is_policy_checked = 0)
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = $(
        if ($result -ne $null) {
            "$($result.name)`.is_disabled = $($result.is_disabled)";
        }
    )
}

$script = @"
DECLARE @NumErrorLogs int;
EXEC master.sys.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'NumErrorLogs',
@NumErrorLogs OUTPUT;
SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12'";
    "Pass" = $(
        if (
            $result.NumberOfLogFiles -eq -1 -or $result.NumberOfLogFiles -ge 12
        ) { $true } else { $false }
    );
    "Note" = "NumberOfLogFiles = $($result.NumberOfLogFiles)";
}

$script = @"
SELECT        name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
FROM            sys.configurations
WHERE        (name = 'default trace enabled')
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'";
    "Pass" = $(
        if (
            $result.value_configured -eq 1 -and $result.value_in_use -eq 1
        ) { $true } else { $false }
    );
    "Note" = "value_configured = $($result.value_configured); value_in_use = $($result.value_in_use)";
}

$script = @"
EXEC xp_loginconfig 'audit level';
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "5.3 Ensure 'Login Auditing' is set to 'failed logins'";
    "Pass" = $(
        if (
            $result.config_value -in ('failure','all')
        ) { $true } else { $false }
    );
    "Note" = "config_value = $($result.config_value)";
}

$script = @"
SELECT        S.name AS 'Audit Name', CASE S.is_state_enabled WHEN 1 THEN 'Y' WHEN 0 THEN 'N' END AS 'Audit Enabled', S.type_desc AS 'Write Location', SA.name AS 'Audit Specification Name', 
                         CASE SA.is_state_enabled WHEN 1 THEN 'Y' WHEN 0 THEN 'N' END AS 'Audit Specification Enabled', SAD.audit_action_name, SAD.audited_result
FROM            sys.server_audit_specification_details AS SAD INNER JOIN
                         sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id INNER JOIN
                         sys.server_audits AS S ON SA.audit_guid = S.audit_guid
WHERE        (SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD'))
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'";
    "Pass" = $(
        $cnau = [bool]($result |
            Where-Object -Property audit_action_name -EQ 'AUDIT_CHANGE_GROUP' |
            Where-Object -Property audited_result -EQ 'SUCCESS AND FAILURE')
        $lgfl = [bool]($result |
            Where-Object -Property audit_action_name -EQ 'FAILED_LOGIN_GROUP' |
            Where-Object -Property audited_result -EQ 'SUCCESS AND FAILURE')
        $lgsd = [bool]($result |
            Where-Object -Property audit_action_name -EQ 'SUCCESSFUL_LOGIN_GROUP' |
            Where-Object -Property audited_result -EQ 'SUCCESS AND FAILURE')
        if (
            $cnau -and $lgfl -and $lgsd
        ) { $true } else { $false }
    );
    "Note" = "CNAU:$cnau LGFL:$lgfl LGSD:$lgsd";
}

$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "6.1 Ensure Database and Application User Input is Sanitized";
    "Pass" = $true;
    "Note" = "Manual check - dependent on application";
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    SELECT        DB_NAME() as database_name, name, permission_set_desc
    FROM            sys.assemblies
    WHERE        (is_user_defined = 1)
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies";
    "Pass" = $(
        if (
            $result.count -eq 0 -or
            ($result | Select-Object -Property permission_set_desc -Unique).permission_set_desc -eq 'SAFE_ACCESS'
        ) { $true } else { $false }
    );
    "Note" = "CLR Assemblies count = $($result.count)";
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    SELECT        DB_NAME() AS Database_Name, name AS Key_Name
    FROM            sys.symmetric_keys
    WHERE        (algorithm_desc NOT IN (''AES_128'', ''AES_192'', ''AES_256'')) AND (DB_ID() > 4)
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = $(
        if ($result -ne $null) {
            "$($result.Database_Name) = $($result.Key_Name);"
        }
    );
}

$script = @"
DECLARE @command varchar(1000)
SELECT @command = '
    USE ?
    SELECT        DB_NAME() AS Database_Name, name AS Key_Name
    FROM            sys.asymmetric_keys
    WHERE        (key_length < 2048) AND (DB_ID() > 4)
'
EXEC sp_MSforeachdb @command
"@
$result = Invoke-Sqlcmd -Query $script
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases";
    "Pass" = $(
        if (
            $result -eq $null
        ) { $true } else { $false }
    );
    "Note" = $(
        if ($result -ne $null) {
            "$($result.Database_Name) = $($result.Key_Name);"
        }
    );
}

$result = (Get-Service 'SQL Server Browser').Status
$raw += [PSCustomObject]@{
    "ComputerName" = $cn;
    "BenchMark" = $bm;
    "Recommendation" = "8.1 Ensure 'SQL Server Browser Service' is configured correctly";
    "Pass" = $(
        if (
            $result -eq 'Stopped' -or ((Get-Service MSSQL*).count -gt 1)
        ) { $true } else { $false }
    );
    "Note" = "MSSQL* = $((Get-Service MSSQL*).count)";
}

return $raw