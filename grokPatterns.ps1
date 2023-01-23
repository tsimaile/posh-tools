<#
.SYNOPSIS
    Regex patterns for  Powershell
.DESCRIPTION
    standard regular expressions patterns for use in Powershell searches using
    * -match
    * -split
    * -replace
    * Select-String
.NOTES
    Author: TS SysTech Team (ts-systech-team@scu.edu.au)
    LastMod: 04-Aug-2020
    Source patterns from
    * https://streamsets.com/documentation/datacollector/latest/help/datacollector/UserGuide/Apx-GrokPatterns/GrokPatterns_title.html
    * https://doc.lucidworks.com/fusion-server/5.1/reference/parser-stages/grok-patterns.html
.EXAMPLE
    '230.165.15.96' -match $grokIPV4
    returns True as valid IPv4
.EXAMPLE
    'examp|e@company.com' -match $grokEMAILADDRESS
    
    returns False as account name contains an invalid character '|'
.EXAMPLE
    'Today is Monday the first day of the week' -split $grokDAY
    
    returns two strings split on any valid day
    1.  Today is 
    2.  the first day of the week
.EXAMPLE
    To match a line with a specific pattern and names Matches

    $line = '13:34:59 230.165.15.96 example@company.com'
    $pattern = "^(?'Time'$grokTIME)\s(?'IPAddress'$grokIPADDRESS)\s(?'EmailAddress'$grokEMAILADDRESS)"
    $line -match $pattern | %{$Matches}

    Name                           Value                                                                                                                                                                                                                             
    ----                           -----                                                                                                                                                                                                                             
    76                                                                                                                                                                                                                                                               
    Time                           13:34:59                                                                                                                                                                                                                          
    EmailAddress                   example@company.com                                                                                                                                                                                                               
    IPAddress                      230.165.15.96                                                                                                                                                                                                                     
    0                              13:34:59 230.165.15.96 example@company.com                                                                                                                                                                                        

    $Matches['Time'] = '13:34:59'
    $Matches['EmailAddress'] = 'example@company.com'
#>

# base
$grokPOSINT = "\b(?:[1-9][0-9]*)\b"
$grokNONNEGINT = "\b(?:[0-9]+)\b"
$grokWORD = "\b\w+\b"
$grokNOTSPACE = "\S+"
$grokSPACE = "\s*"
$grokDATA = ".*?"
$grokGREEDYDATA = ".*"
$grokQUOTEDSTRING = "(?>(?<!\\)(?>`"(?>\\.|[^\\`"]+)+`"|`"`"|(?>'(?>\\.|[^\\']+)+')|''|(?>`(?>\\.|[^\\`]+)+`)|``))"
$grokUUID = "[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}"
$grokURN = "urn:[0-9A-Za-z][0-9A-Za-z-]{0,31}:(?:%[0-9a-fA-F]{2}|[0-9A-Za-z()+,.:=@;`$_!*'/?#-])+"

# networking
$grokCISCOMAC = "(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})"
$grokWINDOWSMAC = "(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})"
$grokCOMMONMAC = "(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})"
$grokMAC = "(?:$grokCISCOMAC|$grokWINDOWSMAC|$grokCOMMONMAC)"
$grokIPV6 = "((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?"
$grokIPV4 = "(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])"
$grokIP = "(?:$grokIPV6|$grokIPV4)"
$grokIPADDRESS = "(?:$grokIPV6|$grokIPV4)"
$grokHOSTNAME = "\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)"
$grokIPORHOST = "(?:$grokIP|$grokHOSTNAME)"
$grokHOSTPORT = "$grokIPORHOST`:$grokPOSINT"

# grok
$grokUSERNAME = "[a-zA-Z0-9._-]+"
$grokUSER = "$grokUSERNAME"
$grokEMAILLOCALPART = "[a-zA-Z][a-zA-Z0-9_.+-=:]+"
$grokEMAILADDRESS = "$grokEMAILLOCALPART@$grokHOSTNAME"
$grokHTTPDUSER = "$grokEMAILADDRESS|$grokUSER"
$grokINT = "(?:[+-]?(?:[0-9]+))"
$grokBASE10NUM = "(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))"
$grokNUMBER = "(?:$grokBASE10NUM)"
$grokBASE16NUM = "(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))"
$grokBASE16FLOAT = "\b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b"

# paths
$grokPATH = "(?:$grokUNIXPATH|$grokWINPATH)"
$grokUNIXPATH = "(/([\w_%!$@:.,+~-]+|\\.)*)+"
$grokTTY = "(?:/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+))"
$grokWINPATH = "(?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+"
$grokURIPROTO = "[A-Za-z]+(\+[A-Za-z+]+)?"
$grokURIHOST = "$grokIPORHOST(?::$grokPOSINT)?"
$grokURIPATH = "(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+"
$grokURIPARAM = "\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*"
$grokURIPATHPARAM = "$grokURIPATH(?:$grokURIPARAM)?"
$grokURI = "$grokURIPROTO`://(?:$grokUSER(?::[^@]*)?@)?(?:$grokURIHOST)?(?:$grokURIPATHPARAM)?"

# Months: January, Feb, 3, 03, 12, December
$grokMONTH = "\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?|[Jj]un(?:e|i)?|[Jj]ul(?:y)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b"
$grokMONTHNUM = "(?:0?[1-9]|1[0-2])"
$grokMONTHNUM2 = "(?:0[1-9]|1[0-2])"
$grokMONTHDAY = "(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])"

# Days: Monday, Tue, Thu, etc...
$grokDAY = "(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)"

# Years?
$grokYEAR = "(?>\d\d){1,2}"
$grokHOUR = "(?:2[0123]|[01]?[0-9])"
$grokMINUTE = "(?:[0-5][0-9])"
# '60' is a leap second in most time standards and thus is valid.
$grokSECOND = "(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)"

$grokTIME = "(?!<[0-9])$grokHOUR`:$grokMINUTE(?::$grokSECOND)(?![0-9])"
$grokDATE_US = "$grokMONTHNUM[/-]$grokMONTHDAY[/-]$grokYEAR"
$grokDATE_EU = "$grokMONTHDAY[./-]$grokMONTHNUM[./-]$grokYEAR"
$grokISO8601_TIMEZONE = "(?:Z|[+-]$grokHOUR(?::?$grokMINUTE))"
$grokISO8601_SECOND = "(?:$grokSECOND|60)"
$grokTIMESTAMP_ISO8601 = "$grokYEAR-$grokMONTHNUM-$grokMONTHDAY[T ]$grokHOUR:?$grokMINUTE(?::?$grokSECOND)?$grokISO8601_TIMEZONE?"
$grokDATE = "$grokDATE_US|$grokDATE_EU"
$grokDATESTAMP = "$grokDATE[- ]$grokTIME"
$grokTZ = "(?:[PMCE][SD]T|UTC)"
$grokDATESTAMP_RFC822 = "$grokDAY $grokMONTH $grokMONTHDAY $grokYEAR $grokTIME $grokTZ"
$grokDATESTAMP_RFC2822 = "$grokDAY, $grokMONTHDAY $grokMONTH $grokYEAR $grokTIME $grokISO8601_TIMEZONE"
$grokDATESTAMP_OTHER = "$grokDAY $grokMONTH $grokMONTHDAY $grokTIME $grokTZ $grokYEAR"
$grokDATESTAMP_EVENTLOG = "$grokYEAR$grokMONTHNUM2$grokMONTHDAY$grokHOUR$grokMINUTE$grokSECOND"
$groHTTPDERROR_DATE = "$grokDAY $grokMONTH $grokMONTHDAY $grokTIME $grokYEAR"

# Syslog Dates: Month Day HH:MM:SS
$grokSYSLOGTIMESTAMP = "$grokMONTH +$grokMONTHDAY $grokTIME"
$grokPROG = "[\x21-\x5a\x5c\x5e-\x7e]+"
$grokSYSLOGPROG = "$grokPROG(?:\[$grokPOSINT\])?"
$grokSYSLOGHOST = "$grokIPORHOST"
$grokSYSLOGFACILITY = "<$grokNONNEGINT.$grokNONNEGINT>"
$grokHTTPDATE = "$grokMONTHDAY/$grokMONTH/$grokYEAR`:$grokTIME $grokINT"

# Shortcuts
$grokQS = "$grokQUOTEDSTRING"

# Log formats
$grokSYSLOGBASE = "$grokSYSLOGTIMESTAMP (?:$grokSYSLOGFACILITY )?$grokSYSLOGHOST $grokSYSLOGPROG`:"
$grokCOMMONAPACHELOG = "$grokIPORHOST $grokHTTPDUSER $grokUSER \[$grokHTTPDATE\] `"(?:$grokWORD $grokNOTSPACE(?: HTTP/$grokNUMBER)?|$grokDATA)`" $grokNUMBER (?:$grokNUMBER|-)"
$grokCOMBINEDAPACHELOG = "$grokCOMMONAPACHELOG $grokQS $grokQS"
$grokHTTPD20_ERRORLOG = "\[$grokHTTPDERROR_DATE\] \[$grokLOGLEVEL\] (?:\[client $grokIPORHOST\] ){0,1$grokGREEDYDATA"
$grokHTTPD24_ERRORLOG = "\[$grokHTTPDERROR_DATE\] \[$grokWORD`:$grokLOGLEVEL\] \[pid $grokPOSINT`:tid $grokNUMBER\]( \($grokPOSINT\)$grokDATA`:)?( \[client $grokIPORHOST`:$grokPOSINT\])? $grokDATA`: $grokGREEDYDATA"
$grokHTTPD_ERRORLOG = "$grokHTTPD20_ERRORLOG|$grokHTTPD24_ERRORLOG"

# Log Levels
$grokLOGLEVEL = "([Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)"

