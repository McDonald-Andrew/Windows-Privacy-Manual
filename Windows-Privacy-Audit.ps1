#requires -RunAsAdministrator
$ErrorActionPreference = 'SilentlyContinue'
# This audit checks only states that can be verified reliably from PowerShell.
# It intentionally does NOT create PASS/CHECK results for:
#   - Settings > Apps > Resume
#   - Settings > Privacy & security > Location > Location services
#   - Office Account Privacy / connected-experience UI controls
#   - Configure Automatic Updates being literally "Not Configured" in Local GPO
#   - absence of the VS Code settings.json file
#   - Local GPO / Registry.pol provenance
#
# Those remain manual/provenance checks. Registry-backed checks below verify
# effective state only; they do not claim the value originated in Registry.pol.
$results = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Category,[string]$Item,[object]$Expected,[object]$Actual,[bool]$Pass,[string]$Method='')
    $results.Add([pscustomobject]@{
        Category=$Category; Item=$Item; Expected="$Expected"; Actual="$Actual";
        Result=$(if($Pass){'PASS'}else{'CHECK'}); Method=$Method
    })
}
function Get-RegValue {
    param([string]$Path,[string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
function Check-Reg {
    param([string]$Category,[string]$Path,[string]$Name,[object]$Expected,[string]$Method='Registry/GPO')
    $actual=Get-RegValue $Path $Name
    Add-Check $Category "$Path\$Name" $Expected $actual ($null -ne $actual -and "$actual" -eq "$Expected") $Method
}

Write-Host "`n=== Windows Privacy / Network Hardening Audit ===" -ForegroundColor Cyan
Write-Host ("Time: " + (Get-Date))
Write-Host ("Computer: " + $env:COMPUTERNAME)

# Services
$svc=Get-Service DiagTrack
Add-Check 'Services' 'DiagTrack startup' 'Disabled' $svc.StartType ($svc.StartType -eq 'Disabled') 'PowerShell'
Add-Check 'Services' 'DiagTrack state' 'Stopped' $svc.Status ($svc.Status -eq 'Stopped') 'PowerShell'
$svc=Get-Service CDPSvc
Add-Check 'Services' 'CDPSvc startup' 'Disabled' $svc.StartType ($svc.StartType -eq 'Disabled') 'PowerShell'
Add-Check 'Services' 'CDPSvc state' 'Stopped' $svc.Status ($svc.Status -eq 'Stopped') 'PowerShell'
Add-Check 'Services' 'CDPUserSvc Start' 4 (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' 'Start') ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' 'Start') -eq 4) 'Registry'
Add-Check 'Services' 'CDPUserSvc UserServiceFlags' 0 (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' 'UserServiceFlags') ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc' 'UserServiceFlags') -eq 0) 'Registry'

# Telemetry / Activity / CDP
Check-Reg 'Telemetry' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
Check-Reg 'Activity/CDP' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 0
Check-Reg 'Activity/CDP' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 0
Check-Reg 'Activity/CDP' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 0
Check-Reg 'Activity/CDP' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableCdp' 0
Check-Reg 'Activity/CDP' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableMmx' 0

# Spotlight / consumer content
$u='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
Check-Reg 'Spotlight' $u 'ConfigureWindowsSpotlight' 0
Check-Reg 'Spotlight' $u 'DisableSpotlightCollectionOnDesktop' 1
Check-Reg 'Spotlight' $u 'DisableTailoredExperiencesWithDiagnosticData' 1
Check-Reg 'Spotlight' $u 'DisableThirdPartySuggestions' 1
Check-Reg 'Spotlight' $u 'DisableWindowsSpotlightFeatures' 1
Check-Reg 'Spotlight' $u 'DisableWindowsSpotlightOnActionCenter' 1
Check-Reg 'Spotlight' $u 'DisableWindowsSpotlightOnSettings' 1
Check-Reg 'Spotlight' $u 'DisableWindowsSpotlightWindowsWelcomeExperience' 1
$m='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
Check-Reg 'Spotlight' $m 'DisableCloudOptimizedContent' 1
Check-Reg 'Spotlight' $m 'DisableConsumerAccountStateContent' 1
Check-Reg 'Spotlight' $m 'DisableWindowsConsumerFeatures' 1

Check-Reg 'Widgets' 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0
Check-Reg 'WNS' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' 'NoCloudApplicationNotification' 1
Check-Reg 'Account' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' 'BlockAADWorkplaceJoin' 1
Check-Reg 'Account' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'NoConnectedUser' 3 'Security Options / registry'
Check-Reg 'Search' 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1

# Windows web-search policies
$searchPolicyPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
Check-Reg 'Search' $searchPolicyPath 'DisableWebSearch' 1
Check-Reg 'Search' $searchPolicyPath 'ConnectedSearchUseWeb' 0

# Sync your settings: master switch and all current per-category "Do not sync" policies.
# Enabled "Do not sync" policies use value 2.  UserOverride=1 means users cannot
# turn that category back on.
$settingSyncPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
$settingSyncPolicies=@(
    'DisableSettingSync',
    'DisableApplicationSettingSync',
    'DisableAppSyncSettingSync',
    'DisableWebBrowserSettingSync',
    'DisableCredentialsSettingSync',
    'DisableDesktopThemeSettingSync',
    'DisablePersonalizationSettingSync',
    'DisableStartLayoutSettingSync',
    'DisableWindowsSettingSync',
    'DisableAccessibilitySettingSync',
    'DisableLanguageSettingSync'
)
foreach($name in $settingSyncPolicies){
    Check-Reg 'Settings Sync' $settingSyncPath $name 2
}

$settingSyncOverridePolicies=@(
    'DisableSettingSyncUserOverride',
    'DisableApplicationSettingSyncUserOverride',
    'DisableAppSyncSettingSyncUserOverride',
    'DisableWebBrowserSettingSyncUserOverride',
    'DisableCredentialsSettingSyncUserOverride',
    'DisableDesktopThemeSettingSyncUserOverride',
    'DisablePersonalizationSettingSyncUserOverride',
    'DisableStartLayoutSettingSyncUserOverride',
    'DisableWindowsSettingSyncUserOverride',
    'DisableAccessibilitySettingSyncUserOverride',
    'DisableLanguageSettingSyncUserOverride'
)
foreach($name in $settingSyncOverridePolicies){
    Check-Reg 'Settings Sync' $settingSyncPath $name 1
}

Check-Reg 'Internet Communication' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' 'NoActiveProbe' 1
Check-Reg 'Internet Communication' 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 0

# "Turn off Help and Support Center Did you know? content" = Enabled -> Headlines=0.
Check-Reg 'Internet Communication' 'HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc' 'Headlines' 0

# "Turn off the Windows Messenger Customer Experience Improvement Program"
# computer policy = Enabled -> CEIP=2.
Check-Reg 'Internet Communication' 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' 'CEIP' 2

Check-Reg 'Delivery Optimization' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 99

# Edge/WebView experimentation
Check-Reg 'Edge' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'ExperimentationAndConfigurationServiceControl' 0
Check-Reg 'Edge' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2' 'ExperimentationAndConfigurationServiceControl' 0
Check-Reg 'Edge' 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'UpdaterExperimentationAndConfigurationServiceControl' 0

# WER and SmartScreen
Check-Reg 'WER' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
$ss=Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
Add-Check 'SmartScreen' 'Explorer SmartScreen policy' 0 $ss ($ss -eq 0) 'GPO'

# Defender
$st=Get-MpComputerStatus
if($st){
    Add-Check 'Defender' 'AntivirusEnabled' $true $st.AntivirusEnabled ($st.AntivirusEnabled -eq $true)
    Add-Check 'Defender' 'RealTimeProtectionEnabled' $true $st.RealTimeProtectionEnabled ($st.RealTimeProtectionEnabled -eq $true)
    Add-Check 'Defender' 'BehaviorMonitorEnabled' $true $st.BehaviorMonitorEnabled ($st.BehaviorMonitorEnabled -eq $true)
    Add-Check 'Defender' 'IoavProtectionEnabled' $true $st.IoavProtectionEnabled ($st.IoavProtectionEnabled -eq $true)
}

# Hosts
$hosts="$env:SystemRoot\System32\drivers\etc\hosts"
$h=Get-Content $hosts
foreach($line in @(
    '0.0.0.0 settings-win.data.microsoft.com',
    ':: settings-win.data.microsoft.com',
    '0.0.0.0 fd.api.iris.microsoft.com',
    ':: fd.api.iris.microsoft.com'
)){
    $found=$h | Where-Object {$_.Trim() -ieq $line}
    Add-Check 'Hosts' $line 'Present' $(if($found){'Present'}else{'Missing'}) ([bool]$found) 'hosts'
}

# StartExperiences package should be absent
$pkg=Get-AppxPackage -AllUsers -Name 'Microsoft.StartExperiencesApp'
Add-Check 'Apps' 'Microsoft.StartExperiencesApp installed' 'Absent' $(if($pkg){'Present'}else{'Absent'}) (-not [bool]$pkg) 'AppX'
$prov=Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq 'Microsoft.StartExperiencesApp'
Add-Check 'Apps' 'Microsoft.StartExperiencesApp provisioned' 'Absent' $(if($prov){'Present'}else{'Absent'}) (-not [bool]$prov) 'AppX'

# Microsoft Teams should remain uninstalled.
# Check modern AppX/MSIX, provisioned state, classic/Machine-Wide Installer entries,
# and legacy per-user executable locations.  The Teams Meeting Add-in is not
# treated as the Teams client.
$teamsAppx=@(
    Get-AppxPackage -AllUsers | Where-Object {
        $_.Name -match '^(MSTeams|MicrosoftTeams|MicrosoftTeamsPreview)$' -or
        $_.PackageFamilyName -match '^(MSTeams|MicrosoftTeams)'
    }
)
$teamsAppxActual=if($teamsAppx){($teamsAppx | Select-Object -ExpandProperty Name -Unique) -join ', '}else{'Absent'}
Add-Check 'Apps' 'Microsoft Teams AppX/MSIX client' 'Absent' $teamsAppxActual (-not [bool]$teamsAppx) 'AppX'

$teamsProv=@(
    Get-AppxProvisionedPackage -Online | Where-Object {
        $_.DisplayName -match '^(MSTeams|MicrosoftTeams|MicrosoftTeamsPreview)$'
    }
)
$teamsProvActual=if($teamsProv){($teamsProv | Select-Object -ExpandProperty DisplayName -Unique) -join ', '}else{'Absent'}
Add-Check 'Apps' 'Microsoft Teams provisioned package' 'Absent' $teamsProvActual (-not [bool]$teamsProv) 'AppX provisioning'

$uninstallRoots=@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$machineUninstallEntries=@(Get-ItemProperty $uninstallRoots)
$teamsUninstall=@(
    $machineUninstallEntries | Where-Object {
        $_.DisplayName -and
        $_.DisplayName -notmatch 'Meeting Add-in' -and
        (
            $_.DisplayName -eq 'Microsoft Teams' -or
            $_.DisplayName -eq 'Teams Machine-Wide Installer' -or
            $_.DisplayName -match '^Microsoft Teams classic' -or
            $_.DisplayName -match '^Microsoft Teams \(work or school\)'
        )
    }
)
$teamsUninstallActual=if($teamsUninstall){($teamsUninstall | Select-Object -ExpandProperty DisplayName -Unique) -join ', '}else{'Absent'}
Add-Check 'Apps' 'Microsoft Teams MSI/classic client' 'Absent' $teamsUninstallActual (-not [bool]$teamsUninstall) 'MSI/uninstall registry'

$legacyTeamsCandidates=@(
    "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe",
    "$env:LOCALAPPDATA\Microsoft\Teams\Update.exe",
    "$env:SystemDrive\Users\*\AppData\Local\Microsoft\Teams\current\Teams.exe",
    "$env:SystemDrive\Users\*\AppData\Local\Microsoft\Teams\Update.exe"
)
$legacyTeamsFound=@($legacyTeamsCandidates | Where-Object { Test-Path $_ })
$legacyTeamsActual=if($legacyTeamsFound){$legacyTeamsFound -join ', '}else{'Absent'}
Add-Check 'Apps' 'Legacy Teams executable' 'Absent' $legacyTeamsActual (-not [bool]$legacyTeamsFound) 'Filesystem'

# Microsoft Edge browser should remain absent while WebView2 Runtime remains present.
$edgeBrowserCandidates=@(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\*\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\*\msedge.exe"
)
$edgeBrowserFiles=@($edgeBrowserCandidates | Where-Object { $_ -and (Test-Path $_) })
$edgeUninstall=@(
    $machineUninstallEntries | Where-Object {
        $_.DisplayName -eq 'Microsoft Edge'
    }
)
$edgeBrowserPresent=([bool]$edgeBrowserFiles -or [bool]$edgeUninstall)
$edgeBrowserActual=if($edgeBrowserPresent){
    (@(
        $edgeBrowserFiles
        $edgeUninstall | ForEach-Object { "Uninstall entry: $($_.DisplayName)" }
    ) -join ', ')
}else{'Absent'}
Add-Check 'Apps' 'Microsoft Edge browser' 'Absent' $edgeBrowserActual (-not $edgeBrowserPresent) 'Installed-app/filesystem'

$webViewCandidates=@(
    "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe",
    "$env:ProgramFiles\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe",
    "$env:LOCALAPPDATA\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe"
)
$webViewFiles=@($webViewCandidates | Where-Object { $_ -and (Test-Path $_) })
$webViewUninstall=@(
    $machineUninstallEntries | Where-Object {
        $_.DisplayName -like 'Microsoft Edge WebView2 Runtime*'
    }
)
$webViewPresent=([bool]$webViewFiles -or [bool]$webViewUninstall)
$webViewActual=if($webViewPresent){
    (@(
        $webViewFiles
        $webViewUninstall | ForEach-Object { "Uninstall entry: $($_.DisplayName)" }
    ) -join ', ')
}else{'Absent'}
Add-Check 'Apps' 'Microsoft Edge WebView2 Runtime' 'Present' $webViewActual $webViewPresent 'Installed-app/filesystem'

# Visual Studio / VS Code
Check-Reg 'Developer tools' 'HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\SQM' 'OptIn' 0
$vscode=Join-Path $env:APPDATA 'Code\User\settings.json'
# Intentionally no CHECK result when the file is absent; this is an excluded condition.
if(Test-Path $vscode){
    $raw=Get-Content $vscode -Raw
    Add-Check 'Developer tools' 'VS Code telemetry.telemetryLevel' 'off' $(if($raw -match '"telemetry\.telemetryLevel"\s*:\s*"off"'){'off'}else{'not found'}) ($raw -match '"telemetry\.telemetryLevel"\s*:\s*"off"') 'settings.json'
    Add-Check 'Developer tools' 'VS Code workbench.enableExperiments' 'false' $(if($raw -match '"workbench\.enableExperiments"\s*:\s*false'){'false'}else{'not found'}) ($raw -match '"workbench\.enableExperiments"\s*:\s*false') 'settings.json'
}

# Account state

# Determine the user who owns Explorer in this PowerShell session, then ask the
# LocalAccounts provider where that principal came from.  PrincipalSource=Local
# is the desired local-SAM state; MicrosoftAccount would indicate an MSA-backed
# Windows sign-in.  If Explorer cannot be resolved, fall back to this process token.
$interactiveSid=$null
$interactiveIdentitySource='Explorer session'
try{
    $currentSessionId=(Get-Process -Id $PID).SessionId
    $explorerProcess=Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" |
        Where-Object { $_.SessionId -eq $currentSessionId } |
        Select-Object -First 1
    if($explorerProcess){
        $ownerSid=Invoke-CimMethod -InputObject $explorerProcess -MethodName GetOwnerSid
        if($ownerSid.ReturnValue -eq 0 -and $ownerSid.Sid){
            $interactiveSid=$ownerSid.Sid
        }
    }
}catch{}

if(-not $interactiveSid){
    $interactiveSid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $interactiveIdentitySource='Audit process token (Explorer owner unavailable)'
}

$localUserCmd=Get-Command Get-LocalUser -ErrorAction SilentlyContinue
if($localUserCmd){
    try{
        $sidObject=[System.Security.Principal.SecurityIdentifier]$interactiveSid
        $interactiveLocalUser=Get-LocalUser -SID $sidObject -ErrorAction Stop
        $principalSource="$($interactiveLocalUser.PrincipalSource)"
        $interactiveActual="$($interactiveLocalUser.Name); SID=$interactiveSid; PrincipalSource=$principalSource; Source=$interactiveIdentitySource"
        Add-Check 'Account' 'Current interactive Windows sign-in source' 'Local SAM (PrincipalSource=Local)' $interactiveActual ($principalSource -eq 'Local') 'Windows identity / LocalAccounts'
    }catch{
        Add-Check 'Account' 'Current interactive Windows sign-in source' 'Local SAM (PrincipalSource=Local)' "Could not resolve SID $interactiveSid with Get-LocalUser" $false 'Windows identity / LocalAccounts'
    }
}else{
    Add-Check 'Account' 'Current interactive Windows sign-in source' 'Local SAM (PrincipalSource=Local)' 'Get-LocalUser unavailable; run 64-bit Windows PowerShell' $false 'Windows identity / LocalAccounts'
}

$ds=(dsregcmd /status) -join "`n"
foreach($p in @(
    @('AzureAdJoined','NO'),@('EnterpriseJoined','NO'),@('DomainJoined','NO'),
    @('WorkplaceJoined','NO'),@('WamDefaultSet','NO'),@('AzureAdPrt','NO'),
    @('EnterprisePrt','NO'),@('NgcSet','NO')
)){
    $name=$p[0]; $expected=$p[1]
    $m=[regex]::Match($ds,"(?m)^\s*$([regex]::Escape($name))\s*:\s*(\S+)")
    $actual=if($m.Success){$m.Groups[1].Value}else{'Not found'}
    Add-Check 'Account' "dsregcmd $name" $expected $actual ($actual -eq $expected) 'Settings/account'
}

# Old DDS firewall experiment should stay gone
$r=Get-NetFirewallRule -DisplayName 'BLOCK Microsoft Device Directory Service'
Add-Check 'Firewall' 'Old DDS firewall rule' 'Absent' $(if($r){'Present'}else{'Absent'}) (-not [bool]$r) 'Firewall cleanup'
$k=Get-NetFirewallDynamicKeywordAddress -AllAutoResolve | Where-Object Keyword -eq 'cs.dds.microsoft.com'
Add-Check 'Firewall' 'Old DDS Dynamic Keyword Address' 'Absent' $(if($k){'Present'}else{'Absent'}) (-not [bool]$k) 'Firewall cleanup'

# Temporary forensic auditing should normally be off
$wfp=(auditpol /get /subcategory:"Filtering Platform Connection" | Out-String)
Add-Check 'Forensics' 'Filtering Platform Connection auditing' 'No Auditing' (($wfp -split "`n"|?{$_ -match 'Filtering Platform Connection'}) -join ' ') ($wfp -match 'No Auditing') 'auditpol'
$pc=(auditpol /get /subcategory:"Process Creation" | Out-String)
Add-Check 'Forensics' 'Process Creation auditing' 'No Auditing' (($pc -split "`n"|?{$_ -match 'Process Creation'}) -join ' ') ($pc -match 'No Auditing') 'auditpol'

$results | Sort-Object Category,Item | Format-Table -AutoSize -Wrap
$needs=$results | Where-Object Result -eq 'CHECK'
Write-Host "`n$($results.Count) static checks; $($needs.Count) need review." -ForegroundColor $(if($needs){'Yellow'}else{'Green'})

Write-Host "`nManual / intentionally excluded from automatic PASS-CHECK results:" -ForegroundColor Cyan
Write-Host "  Settings > Apps > Resume = Off"
Write-Host "  Settings > Privacy & security > Location > Location services = Off"
Write-Host "  Office Account Privacy = your maximally restricted state"
Write-Host "  Local GPO: Configure Automatic Updates = Not Configured"
Write-Host "  Local GPO / Registry.pol provenance: verify separately with gpresult, RSOP, or LGPO tooling if desired"
Write-Host "  VS Code settings.json absence is not treated as a failure; VS Code values are checked only when the file exists"

$out=Split-Path -Parent $MyInvocation.MyCommand.Path
if(-not $out){$out=(Get-Location).Path}
$csv=Join-Path $out ("Windows-Privacy-Audit-"+(Get-Date -Format 'yyyyMMdd-HHmmss')+".csv")
$results | Export-Csv $csv -NoTypeInformation
Write-Host "`nCSV report: $csv" -ForegroundColor Cyan
