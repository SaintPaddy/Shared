#requires -RunAsAdministrator
# Hardened AD Health Collector - "admin-proof" edition
# - Creates C:\temp_ad_health_log\AD-Health_<timestamp>\ + ZIP
# - Never aborts on errors; logs and continues
# - Echoes each command in output headers + manifest.csv
# - Runs ipconfig /all per DC (remoting optional)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Off

# -------- Paths & timestamp --------
$timestamp = (Get-Date).ToString('yyyy-MM-dd__HH-mm')
$base = 'C:\temp_ad_health_log'
$out  = Join-Path $base "AD-Health_$timestamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null

# Start a console transcript (best-effort)
try { Start-Transcript -Path (Join-Path $out 'console_transcript.txt') -Force | Out-Null } catch {}

# -------- Manifest helper (maps command -> output file etc.) --------
$Manifest = New-Object System.Collections.Generic.List[Object]
function Add-Manifest {
    param(
        [string]$Command,[string]$OutputPath,[string]$Target = $env:COMPUTERNAME,
        [string]$Status = 'OK',[datetime]$Start,[datetime]$End
    )
    $Manifest.Add([pscustomobject]@{
        DateTime  = $timestamp; Target = $Target; Command = $Command
        Output    = $OutputPath; Status = $Status; Start = $Start; End = $End
    })
}

function Write-Header {
    param([string]$Path,[string]$Command,[string]$Target)
@"
# AD Health Report
# DateTime: $timestamp
# Target:   $Target
# Command:  $Command
# ------------------------------------------------------------

"@ | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Invoke-Logged {
    param([scriptblock]$Script,[string]$Label,[string]$OutPath,[string]$Target = $env:COMPUTERNAME)
    $start = Get-Date; $status = 'OK'
    try {
        Write-Header -Path $OutPath -Command $Label -Target $Target
        & $Script 2>&1 | Out-File -FilePath $OutPath -Append -Encoding UTF8
    } catch {
        $_ | Out-File -FilePath $OutPath -Append -Encoding UTF8
        $status = 'ERROR'
    }
    Add-Manifest -Command $Label -OutputPath $OutPath -Target $Target -Status $status -Start $start -End (Get-Date)
}

function Invoke-ExternalLogged {
    param([string]$CommandLine,[string]$OutPath,[string]$Target = $env:COMPUTERNAME)
    Invoke-Logged -Label $CommandLine -OutPath $OutPath -Target $Target -Script { cmd.exe /c $using:CommandLine }
}

function Export-WithTimestamp { param([Parameter(ValueFromPipeline=$true)]$InputObject,[string]$Path)
    process { $InputObject | Select-Object @{n='DateTime';e={$timestamp}}, * } |
      Export-Csv -NoTypeInformation -Path $Path
}

# -------- Try ActiveDirectory module; set fallbacks --------
$HasADModule = $false
try { Import-Module ActiveDirectory -ErrorAction Stop; $HasADModule = $true } catch {
    "ActiveDirectory module not found; running with fallbacks." | Out-File (Join-Path $out 'warning_no_ad_module.txt')
}

# Get domain & PDC (works without AD module too)
try {
    if ($HasADModule) {
        $domain = (Get-ADDomain).DNSRoot
        $pdc    = (Get-ADDomain).PDCEmulator
    } else {
        $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        $pdc    = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name
    }
} catch {
    $domain = $env:USERDNSDOMAIN
    $pdc = ($env:LOGONSERVER -replace '\\','')
}

# -------- DC inventory --------
if ($HasADModule) {
    $DCs = Get-ADDomainController -Filter * | Select HostName, IPv4Address, Site, IsGlobalCatalog, Enabled, OperatingSystem
    $DCs | Export-WithTimestamp -Path (Join-Path $out 'dcs.csv')
    $dcHostnames = $DCs.HostName
} else {
    # Fallback: at least collect local DC info
    $dcHostnames = @($env:COMPUTERNAME)
    [pscustomobject]@{
        DateTime=$timestamp; HostName=$env:COMPUTERNAME; IPv4Address=([string](Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ?{$_.IPAddress -ne '127.0.0.1'} | Select -ExpandProperty IPAddress -First 1));
        Site="(unknown)"; IsGlobalCatalog="(unknown)"; Enabled="(unknown)"; OperatingSystem=(Get-CimInstance Win32_OperatingSystem).Caption
    } | Export-Csv -NoTypeInformation -Path (Join-Path $out 'dcs.csv')
}

# -------- Forest/Domain/FSMO --------
if ($HasADModule) {
    (Get-ADForest | Select ForestMode,RootDomain,Domains,GlobalCatalogs) | Export-WithTimestamp -Path (Join-Path $out 'forest.csv')
    (Get-ADDomain  | Select DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster,DomainSID) | Export-WithTimestamp -Path (Join-Path $out 'domain.csv')
} else {
    "[No AD module] Forest/Domain detail limited." | Out-File (Join-Path $out 'forest_domain_limited.txt')
}
Invoke-ExternalLogged -CommandLine 'netdom query fsmo' -OutPath (Join-Path $out 'fsmo.txt')

# -------- DCDIAG (full + DNS) --------
Invoke-ExternalLogged -CommandLine 'dcdiag /e /c /q'        -OutPath (Join-Path $out 'dcdiag_summary.txt')
Invoke-ExternalLogged -CommandLine 'dcdiag /test:DNS /e /v' -OutPath (Join-Path $out 'dcdiag_dns_verbose.txt')

# -------- Replication (repadmin + AD cmdlets if present) --------
Invoke-ExternalLogged -CommandLine 'repadmin /replsummary' -OutPath (Join-Path $out 'repadmin_replsummary.txt')
Invoke-ExternalLogged -CommandLine 'repadmin /showrepl *'  -OutPath (Join-Path $out 'repadmin_showrepl.txt')
cmd.exe /c 'repadmin /showrepl * /csv' > (Join-Path $out 'repadmin_showrepl.csv')

if ($HasADModule) {
    Invoke-Logged -Label 'Get-ADReplicationPartnerMetadata -Scope Forest' -OutPath (Join-Path $out 'replication_partner_metadata.csv') -Script {
        Get-ADReplicationPartnerMetadata -Scope Forest |
          Select @{n='DateTime';e={$using:timestamp}},Server,Partner,LastReplicationResult,ConsecutiveReplicationFailures,LastReplicationSuccess |
          Export-Csv -NoTypeInformation
    }
    Invoke-Logged -Label 'Get-ADReplicationFailure -Scope Forest' -OutPath (Join-Path $out 'replication_failures.csv') -Script {
        Get-ADReplicationFailure -Scope Forest |
          Select @{n='DateTime';e={$using:timestamp}},Server,Partner,FirstFailureTime,FailureCount,LastError |
          Export-Csv -NoTypeInformation
    }
    foreach ($dc in $dcHostnames) {
        Invoke-Logged -Label "Get-ADReplicationPartnerMetadata -Target $dc" -OutPath (Join-Path $out "replication_partner_$($dc -replace '[\\/:*?""<>|]','_').txt") -Target $dc -Script {
            Get-ADReplicationPartnerMetadata -Target $using:dc |
              Sort-Object Partner | Format-Table Server,Partner,LastReplicationResult,ConsecutiveReplicationFailures,LastReplicationSuccess -AutoSize
        }
    }
} else {
    "[No AD module] Skipping Get-ADReplication* cmdlets." | Out-File (Join-Path $out 'replication_cmdlets_skipped.txt')
}

# -------- SYSVOL/DFSR --------
Invoke-ExternalLogged -CommandLine 'dfsrmig /GetGlobalState'     -OutPath (Join-Path $out 'dfsr_migration_state.txt')
Invoke-ExternalLogged -CommandLine 'dfsrdiag ReplicationState'   -OutPath (Join-Path $out 'dfsr_state.txt')

# -------- Time service --------
Invoke-ExternalLogged -CommandLine 'w32tm /monitor'        -OutPath (Join-Path $out 'time_monitor.txt')
Invoke-ExternalLogged -CommandLine 'w32tm /query /status'  -OutPath (Join-Path $out 'time_status.txt')

# -------- DNS SRV records --------
Invoke-Logged -Label "Resolve-DnsName _ldap._tcp.dc._msdcs.$domain -Type SRV -Server $pdc" -OutPath (Join-Path $out 'dns_srv_ldap_dc_msdcs.txt') -Script {
    try {
        Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$using:domain" -Type SRV -Server $using:pdc | Format-Table NameTarget,Port,TTL -AutoSize
    } catch {
        "Resolve-DnsName failed. Try: nslookup -type=SRV _ldap._tcp.dc._msdcs.$using:domain $using:pdc" 
    }
}

# -------- Event logs (last 7 days, errors) --------
$since = (Get-Date).AddDays(-7)
Invoke-Logged -Label "Directory Service errors since $since" -OutPath (Join-Path $out 'events_directory_service_errors.txt') -Script {
    Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Level=2; StartTime=$using:since} |
      Select TimeCreated,Id,LevelDisplayName,ProviderName,Message,MachineName
}
Invoke-Logged -Label "DFS Replication errors since $since" -OutPath (Join-Path $out 'events_dfsr_errors.txt') -Script {
    Get-WinEvent -FilterHashtable @{LogName='DFS Replication'; Level=2; StartTime=$using:since} |
      Select TimeCreated,Id,LevelDisplayName,ProviderName,Message,MachineName
}
Invoke-Logged -Label "DNS Server errors since $since" -OutPath (Join-Path $out 'events_dns_server_errors.txt') -Script {
    Get-WinEvent -FilterHashtable @{LogName='DNS Server'; Level=2; StartTime=$using:since} |
      Select TimeCreated,Id,LevelDisplayName,ProviderName,Message,MachineName
}

# -------- Secure channel test on each DC (remoting optional) --------
foreach ($dc in $dcHostnames) {
    $file = Join-Path $out ("secure_channel_" + ($dc -replace '[\\/:*?""<>|]','_') + ".txt")
    $label = "Test-ComputerSecureChannel -Server $pdc"
    $start = Get-Date; $status = 'OK'
    Write-Header -Path $file -Command $label -Target $dc
    try {
        if ($dc -ieq $env:COMPUTERNAME) {
            Test-ComputerSecureChannel -Server $pdc -Verbose | Out-File -FilePath $file -Append -Encoding UTF8
        } else {
            Invoke-Command -ComputerName $dc -ScriptBlock { Test-ComputerSecureChannel -Server $using:pdc -Verbose } |
                Out-File -FilePath $file -Append -Encoding UTF8
        }
    } catch {
        "Remoting failed or cmdlet not available. On $dc run: nltest /sc_verify:$domain" |
            Out-File -FilePath $file -Append -Encoding UTF8
        $status = 'WARN'
    }
    Add-Manifest -Command $label -OutputPath $file -Target $dc -Status $status -Start $start -End (Get-Date)
}

# -------- ipconfig /all on each DC (remoting optional) --------
foreach ($dc in $dcHostnames) {
    $file = Join-Path $out ("ipconfig_all_" + ($dc -replace '[\\/:*?""<>|]','_') + ".txt")
    Invoke-Logged -Label 'ipconfig /all' -OutPath $file -Target $dc -Script {
        if ($using:dc -ieq $env:COMPUTERNAME) {
            cmd.exe /c 'ipconfig /all'
        } else {
            Invoke-Command -ComputerName $using:dc -ScriptBlock { cmd.exe /c 'ipconfig /all' }
        }
    }
}

# -------- OPTIONAL: per-DC DNS server list --------
foreach ($dc in $dcHostnames) {
    $file = Join-Path $out ("dns_server_list_" + ($dc -replace '[\\/:*?""<>|]','_') + ".txt")
    Invoke-Logged -Label 'Get-DnsClientServerAddress -AddressFamily IPv4' -OutPath $file -Target $dc -Script {
        try {
            if ($using:dc -ieq $env:COMPUTERNAME) {
                Get-DnsClientServerAddress -AddressFamily IPv4 | Sort-Object InterfaceAlias | Format-Table InterfaceAlias, ServerAddresses -AutoSize
            } else {
                Invoke-Command -ComputerName $using:dc -ScriptBlock {
                    Get-DnsClientServerAddress -AddressFamily IPv4 | Sort-Object InterfaceAlias | Format-Table InterfaceAlias, ServerAddresses -AutoSize
                }
            }
        } catch { "Unable to query DNS client server addresses." }
    }
}

# ===== Advanced extras (optional but recommended) =====

# 1) RID Manager health (prevents RID exhaustion/misconfig)
Invoke-ExternalLogged -CommandLine 'dcdiag /test:ridmanager /v' -OutPath (Join-Path $out 'dcdiag_ridmanager.txt')

# 2) Duplicate SPNs (Kerberos breakage detector)
Invoke-ExternalLogged -CommandLine 'setspn -X' -OutPath (Join-Path $out 'spn_duplicates.txt')

# 3) GC coverage per site (you want ≥1 GC per site)
try {
    if ($DCs) {
        $gcBySite = $DCs | Group-Object Site | ForEach-Object {
            [pscustomobject]@{
                DateTime = $timestamp
                Site     = $_.Name
                DCs      = $_.Count
                GCs      = ($_.Group | Where-Object {$_.IsGlobalCatalog}).Count
            }
        }
        $gcBySite | Export-Csv -NoTypeInformation -Path (Join-Path $out 'sites_gc_coverage.csv')
    }
} catch {}

# 4) Sites/Subnets inventory (eyeball DC IPs vs defined subnets)
if ($HasADModule) {
    try {
        Get-ADReplicationSubnet -Filter * |
          Select-Object @{n='DateTime';e={$timestamp}},Name,Site |
          Export-Csv -NoTypeInformation -Path (Join-Path $out 'ad_subnets.csv')
    } catch {
        $_ | Out-File (Join-Path $out 'ad_subnets_error.txt')
    }
}

# 5) Port reachability matrix (LDAP/LDAPS/Kerberos/GC/DNS/NTP)
try {
    $ports = 389,636,3268,3269,88,445,53,123
    $targets = @()
    if ($DCs) { $targets = $DCs.HostName } else { $targets = @($env:COMPUTERNAME) }
    $rows = foreach ($dc in $targets) {
        foreach ($p in $ports) {
            $ok = $false
            try { $ok = Test-NetConnection -ComputerName $dc -Port $p -InformationLevel Quiet } catch {}
            [pscustomobject]@{ DateTime=$timestamp; DC=$dc; Port=$p; Reachable=$ok }
        }
    }
    $rows | Export-Csv -NoTypeInformation -Path (Join-Path $out 'ports_reachability.csv')
} catch {}

# 6) DNS scavenging/aging + zones (audit stale-A defenses)
try {
    Import-Module DnsServer -ErrorAction Stop
    # server-level scavenging
    Invoke-Logged -Label "Get-DnsServerScavenging -ComputerName $pdc" -OutPath (Join-Path $out 'dns_scavenging.txt') -Target $pdc -Script {
        Get-DnsServerScavenging -ComputerName $using:pdc
    }
    # zone inventory
    $zones = Get-DnsServerZone -ComputerName $pdc -ErrorAction Stop
    $zones | Select-Object @{n='DateTime';e={$timestamp}},ZoneName,ZoneType,IsDsIntegrated,IsReverseLookupZone |
        Export-Csv -NoTypeInformation -Path (Join-Path $out 'dns_zones.csv')
    # per-zone aging settings
    foreach ($z in $zones) {
        try {
            Get-DnsServerZoneAging -ComputerName $pdc -Name $z.ZoneName |
              Select-Object @{n='DateTime';e={$timestamp}},ZoneName,ScavengingState,NoRefreshInterval,RefreshInterval |
              Export-Csv -NoTypeInformation -Append -Path (Join-Path $out 'dns_zone_aging.csv')
        } catch {}
    }
} catch {
    "DNS Server module not available here; skipping scavenging/aging detail." | Out-File (Join-Path $out 'dns_scavenging_missing.txt')
}

# 7) Trusts overview (know dependencies before moving DCs)
if ($HasADModule) {
    try {
        Get-ADTrust -Filter * |
          Select-Object @{n='DateTime';e={$timestamp}},Name,Source,Target,TrustType,TrustDirection,ForestTransitive,SelectiveAuthentication |
          Export-Csv -NoTypeInformation -Path (Join-Path $out 'trusts.csv')
    } catch { $_ | Out-File (Join-Path $out 'trusts_error.txt') }
}

# 8) NTDS storage headroom (DIT size and free space on this DC)
try {
    $ntdsParams = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $ditPath    = $ntdsParams.'DSA Database file'
    $logPath    = $ntdsParams.'Database log files path'
    $ditInfo    = Get-Item $ditPath -ErrorAction Stop
    $driveName  = (Get-Item $ditPath).PSDrive.Name
    $driveInfo  = Get-PSDrive -Name $driveName
    [pscustomobject]@{
        DateTime=$timestamp; DITPath=$ditPath; DITSizeBytes=$ditInfo.Length;
        LogPath=$logPath; Drive=("$driveName:`\" ); FreeBytes=$driveInfo.Free; UsedBytes=$driveInfo.Used; CapacityBytes=$driveInfo.Maximum
    } | Export-Csv -NoTypeInformation -Path (Join-Path $out 'ntds_storage.csv')
} catch { $_ | Out-File (Join-Path $out 'ntds_storage_error.txt') }

# 9) NLTEST DC list (quick cross-check)
Invoke-ExternalLogged -CommandLine "nltest /dclist:$domain" -OutPath (Join-Path $out 'nltest_dclist.txt')

# -------- Save manifest & ZIP --------
$Manifest | Select DateTime,Target,Command,Output,Status,Start,End |
    Export-Csv -NoTypeInformation -Path (Join-Path $out 'manifest.csv')

try { Stop-Transcript | Out-Null } catch {}

# Create ZIP for emailing
$zip = Join-Path $base ("AD-Health_" + $timestamp + ".zip")
try {
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip -Force
} catch {
    "ZIP creation failed: $($_.Exception.Message)" | Out-File (Join-Path $out 'zip_error.txt')
}

Write-Host ""
Write-Host "AD health collected to: $out"
Write-Host "ZIP archive: $zip"
# Always exit 0 so non-technical admins don't panic
exit 0
