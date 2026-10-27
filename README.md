# Windows Privacy Hardening: Canonical Manual Configuration and Audit Coverage

Snapshot date: 2026-08-30

This document is meant to be a reusable configuration model. It maps every removed or blocked endpoint and every disabled, stopped, or removed Windows/application component from `Windows-Privacy-Network-Manifest.md` to the correct control surface.

It also audits the current `Windows-Privacy-Audit.ps1` and states exactly what that script verifies, what it only partially verifies, and what it does not verify.

## 1. Canonical configuration model

| Configuration type                        | Canonical owner                              | Preferred manual method                                                            |
| ----------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------- |
| Administrative Template policy            | Local Group Policy object and `Registry.pol` | `gpedit.msc`, or Microsoft `LGPO.exe` when a friendly ADMX entry is unavailable    |
| Security Options policy                   | Local security-policy database               | `secpol.msc` or the Security Settings branch of Local Group Policy                 |
| Windows service state                     | Service Control Manager                      | `services.msc` or `sc.exe`                                                         |
| Microsoft Defender state                  | Defender configuration provider              | Windows Security, Defender Group Policy, or supported `Set-MpPreference` cmdlets   |
| Hostname sinkhole                         | Hosts file                                   | Edit `%SystemRoot%\System32\drivers\etc\hosts` as administrator                    |
| Removed application/package               | AppX, MSI, or application installation state | Settings > Apps when exposed; otherwise the appropriate AppX/MSI removal mechanism |
| Account and device identity               | Windows identity subsystem                   | Settings > Accounts, `secpol.msc`, and `dsregcmd` verification                     |
| Settings-only or application-only feature | Owning Settings/app UI                       | Windows Settings, Office privacy UI, or application settings                       |

Microsoft's LGPO utility can import and apply Registry Policy files and LGPO text, and can export the current Local GPO. That is the clean way to automate Local Group Policy while keeping `Registry.pol` as the authoritative store.

### Important exceptions

1. Some settings do not have a stock Group Policy UI even though they can be represented as registry policy. Use `LGPO.exe` to put those records into `Registry.pol` rather than writing the live policy registry directly.
2. `CDPUserSvc\UserServiceFlags` is service-template metadata, not an ordinary Administrative Template policy and not a normal Services.msc property. Exact parity with the original machine may require a manual Registry Editor change under the service template. This is the narrow exception to the service-only rule.
3. `Microsoft.StartExperiencesApp` might not be exposed in Settings > Installed apps. Exact package removal may require AppX tooling. There is no honest GPO substitute for an application that was actually removed.
4. Edge browser uninstallation is build, region, and servicing-state dependent. Do not remove Microsoft Edge WebView2 Runtime; applications depend on it and it must continue receiving security updates.
5. The current Defender preservation baseline covers engine health only: antivirus, real-time protection, behavior monitoring, and downloaded-file scanning must remain enabled. It does not claim to audit every Defender privacy, cloud-protection, or experimentation preference.

## 2. Canonical control catalog

Each control has an ID. The endpoint and component coverage tables later in this document reference these IDs.

### 2.1 Local Group Policy and Registry.pol controls

#### GPO-01 - Windows diagnostic data

Open: `Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds`.

Configure `Allow Diagnostic Data` to `Enabled > Diagnostic data off (not recommended)`. Older ADMX versions may call this policy `Allow Telemetry`.

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry = 0`.

- This policy works with SCM-02, because the `DiagTrack` service was also disabled.

#### GPO-02 - Widgets

Open: `Computer Configuration > Administrative Templates > Windows Components > Widgets`.

Set to `Disabled`: `Allow widgets`

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests = 0`.

#### GPO-03 - Windows Spotlight and consumer content

Open: `User Configuration > Administrative Templates > Windows Components > Cloud Content`

Set these to `Enabled`:

- `Turn off Spotlight collection on Desktop`
- `Do not use diagnostic data for tailored experiences`
- `Do not suggest third-party content in Windows spotlight`
- `Turn off all Windows spotlight features`
- `Turn off Windows Spotlight on Action Center`
- `Turn off Windows Spotlight on Settings`
- `Turn off the Windows Welcome Experience`

Set to `Disabled`: `Configure Windows spotlight on lock screen`.

Computer policies:

Open: `Computer Configuration > Administrative Templates > Windows Components > Cloud Content`

Set these to `Enabled`:

- `Turn off cloud optimized content`
- `Turn off cloud consumer account state content`
- `Turn off Microsoft consumer experiences`
- Unrelated, but can also enable `Disable Copilot Pin Screen`

Expected effective values under: `HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent`

- `ConfigureWindowsSpotlight = 2`
- `DisableSpotlightCollectionOnDesktop = 1`
- `DisableTailoredExperiencesWithDiagnosticData = 1`
- `DisableThirdPartySuggestions = 1`
- `DisableWindowsSpotlightFeatures = 1`
- `DisableWindowsSpotlightOnActionCenter = 1`
- `DisableWindowsSpotlightOnSettings = 1`
- `DisableWindowsSpotlightWindowsWelcomeExperience = 1`

Expected effective values under: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent`

- `DisableCloudOptimizedContent = 1`
- `DisableConsumerAccountStateContent = 1`
- `DisableWindowsConsumerFeatures = 1`

#### GPO-04 - Activity Feed and user-activity upload

Open: `Computer Configuration > Administrative Templates > System > OS Policies`

Set these to `Disabled`:

- `Enable Activity Feed`
- `Allow publishing of User Activities`
- `Allow upload of User Activities`

Expected effective values under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System`:

- `EnableActivityFeed = 0`
- `PublishUserActivities = 0`
- `UploadUserActivities = 0`

#### GPO-05 - Windows Push Notification Service network use

Open: `Computer Configuration > Administrative Templates > Start Menu and Taskbar > Notifications`

Set to `Enabled`: `Turn off notifications network usage`

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification = 1`.

#### GPO-06 - Windows Search web integration

Open: `Computer Configuration > Administrative Templates > Windows Components > Search`

Set these to `Enabled`:

- `Do not allow web search`
- `Don't search the web or display web results in Search`

Expected effective values under: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search`

- `ConnectedSearchUseWeb = 0`
- `DisableWebSearch = 1`

Expected effective value: `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions = 1`.

- If no friendly ADMX item is available, import it into the User `Registry.pol` with `LGPO.exe`.

#### GPO-07 - NCSI active connectivity probes

Open: `Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings`

Set to `Enabled`: `Turn off Windows Network Connectivity Status Indicator active tests`

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\NoActiveProbe = 1`.

#### GPO-08 - CEIP and Internet Communication content

In the same Internet Communication settings folder (GPO-07), set these to `Enabled`:

- `Turn off Windows Customer Experience Improvement Program`
- `Turn off Help and Support Center "Did you know?" content`
- `Turn off the Windows Messenger Customer Experience Improvement Program`

Expected effective values:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable = 0`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc\Headlines=0`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client\CEIP=2`

#### GPO-09 - Windows settings synchronization

Open: `Computer Configuration > Administrative Templates > Windows Components > Sync your settings`

Set to `Enabled`: `Do not sync`

- Optionally `Do not sync accessibility settings`
- Optionally `Do not sync Apps`
- Optionally `Do not sync app settings`
- Optionally `Do not sync passwords`
- Optionally `Do not sync desktop personalization`
- Optionally `Do not sync language preference settings`
- Optionally `Do not sync personalize`
- Optionally `Do not sync start settings`
- Optionally `Do not sync on metered connections`
- Optionally `Do not sync browser settings`
- Optionally `Do not sync other Windows settings`

Expected effective values under: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync`

- `DisableSettingSync=2`
- `DisableSettingSyncUserOverride=1`

#### GPO-10 - Cross-device experiences and Phone-PC linking

Open: `Computer Configuration > Administrative Templates > System > Group Policy`

Set these to `Disabled`:

- `Continue experiences on this device`
- `Phone-PC linking on this device`

Expected effective values under: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System`

- `EnableCdp = 0`
- `EnableMmx = 0`

#### GPO-11 - Block Workplace Join

Preferred policy: If the ADMX entry exists, open `Computer Configuration > Administrative Templates > Windows Components > Workplace Join` and enable the policy that blocks Microsoft Entra/AAD Workplace Join.

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\BlockAADWorkplaceJoin = 1`.

- Optionally import it as a Machine policy record with `LGPO.exe` when `Registry.pol` provenance and repeatable deployment are required.
- This policy supplements ID-01; it does not replace disconnecting an existing work or school registration.

#### GPO-12 - Windows Error Reporting

Open: `Computer Configuration > Administrative Templates > Windows Components > Windows Error Reporting`

Set to `Enabled`: `Disable Windows Error Reporting`

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled = 1`.

- The scheduled task and `wermgr.exe` can still launch. Success means no external Watson/WER upload, not that the process is forbidden from existing.

#### GPO-13 - Explorer SmartScreen

Open: `Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer`

Set to `Disabled`: `Configure Windows Defender SmartScreen`

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen=0`

- This disables the Explorer/application-reputation surface.

#### GPO-14 - Delivery Optimization Simple mode

Open: `Computer Configuration > Administrative Templates > Windows Components > Delivery Optimization`

Set to `Enabled`: `Download Mode` and configure as `Simple (99)`.

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode=99`

- This disables Delivery Optimization cloud coordination and peer caching while preserving direct update downloads.

#### GPO-15 - Microsoft Edge ECS

Install the current Microsoft Edge administrative templates if needed.

Open: `Administrative Templates > Microsoft Edge`

Configure `Control communication with the Experimentation and Configuration Service` as `RestrictedMode (0)`.

Expected policy value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExperimentationAndConfigurationServiceControl = 0`.

#### GPO-16 - Microsoft Edge WebView2 ECS

Install the current WebView2 administrative template if needed.

Open: `Administrative Templates > Microsoft Edge WebView2`

Configure `Control communication with the Experimentation and Configuration Service` as `RestrictedMode (0)`.

Expected policy value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\WebView2\ExperimentationAndConfigurationServiceControl = 0`.

#### GPO-17 - Microsoft Edge Update ECS

Install the current Microsoft Edge Update administrative template if needed.

Open: `Administrative Templates > Microsoft Edge Update > Microsoft Edge Update`

Set to `Disabled`: `Control updater's communication with the Experimentation and Configuration Service`

Expected policy value: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate\UpdaterExperimentationAndConfigurationServiceControl = 0`.

- Do not disable WebView2 Runtime updates themselves.

#### GPO-18 - Visual Studio SQM

Desired policy record: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VisualStudio\SQM\OptIn = 0`.

- If a Visual Studio administrative template exposes this setting, configure it there.
- Otherwise import the Machine policy record through LGPO text so it lives in `Registry.pol`.
- The policy is inert if full Visual Studio is not installed, but it is still a useful reusable baseline.

### 2.2 Service Control Manager controls

#### SCM-01 - CDPSvc

Open `services.msc`:

- Service: `Connected Devices Platform Service`
- Service name: `CDPSvc`
- Stop the service.
- Set Startup type to `Disabled`.

Expected effective value: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc\Start=4`

#### SCM-02 - DiagTrack

Open `services.msc`:

- Service: `Connected User Experiences and Telemetry`
- Service name: `DiagTrack`
- Stop the service.
- Set Startup type to `Disabled`.

Expected effective value: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Start=4`

#### SCM-03 - CDPUserSvc service template

- Disable the base `CDPUserSvc` service template through Service Control Manager where supported, for example with `sc.exe config CDPUserSvc start= disabled` from an elevated Command Prompt.
- Verify the template's Start value is 4.
- Because `UserServiceFlags` is not exposed by Services.msc or normal `sc.exe` configuration, use Registry Editor only for this service-template metadata if the value is required.

Expected effective values under: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc`

- `Start=4`
- `UserServiceFlags = 0`

### 2.3 Microsoft Defender preservation control

#### DEF-01 - Defender engine health

Expected effective values from `Get-MpComputerStatus`:

- `AntivirusEnabled = True`
- `RealTimeProtectionEnabled = True`
- `BehaviorMonitorEnabled = True`
- `IoavProtectionEnabled = True`

Expected policy-backed values in Registry Editor, when the corresponding policies are explicitly configured, under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`:

- `DisableRealtimeMonitoring = 0`
- `DisableBehaviorMonitoring = 0`
- `DisableIOAVProtection = 0`

`AntivirusEnabled` has no single authoritative Registry Editor equivalent, so verify it with `Get-MpComputerStatus`.

These health states do not verify every Defender preference, including Block at First Sight, cloud-delivered protection, sample submission, or Defender experimentation/configuration controls. Do not use the legacy `DisableAntiSpyware` value as proof of the current Defender antivirus state.

### 2.4 Hosts-file controls

Edit `$env:SystemRoot\System32\drivers\etc\hosts` as administrator.

#### HOST-01 - Windows diagnostic-configuration endpoint

Add:

```text
0.0.0.0 settings-win.data.microsoft.com
:: settings-win.data.microsoft.com
```

#### HOST-02 - Windows Spotlight Iris endpoint

Add:

```text
0.0.0.0 fd.api.iris.microsoft.com
:: fd.api.iris.microsoft.com
```

Flush the resolver cache after changing the file.

### 2.5 Package and application-state controls

#### APP-01 - Microsoft.StartExperiencesApp removed

- Canonical owner: AppX package state.
- Remove the installed package for all applicable users.
- Remove its provisioned package so it is not re-added for new profiles.
- Use Settings > Installed apps if the package is exposed there.
- If it is not exposed, AppX tooling is required. There is no Local GPO that is equivalent to removing the package.

#### APP-02 - Microsoft Teams removed

- Open `Settings > Apps > Installed apps`.
- Uninstall Microsoft Teams and any Teams Machine-Wide Installer entry if present.

#### APP-03 - Microsoft Edge browser removed, WebView2 kept

- Open `Settings > Apps > Installed apps`.
- Uninstall Microsoft Edge only if the installed Windows build exposes a supported Uninstall action.
- Keep Microsoft Edge WebView2 Runtime installed.
- Keep WebView2 and Edge Update security servicing enabled.

#### APP-04 - VS Code privacy settings

In VS Code Settings or `settings.json`:

- `telemetry.telemetryLevel = "off"`
- `workbench.enableExperiments = false`

### 2.6 Account and identity controls

ID-01 and ID-02 are account and identity actions, not Administrative Template `Registry.pol` items. ID-03 is a Security Options policy stored in the local security-policy database.

#### ID-01 - Disconnect work or school registration

Open: `Settings > Accounts > Access work or school`

- Select each unwanted connected work/school account.
- Choose `Disconnect`.
- Verify `WorkplaceJoined : NO` with `dsregcmd /status`.

#### ID-02 - Use a local Windows account

Open: `Settings > Accounts > Your info`

- Choose `Sign in with a local account instead`.
- Complete the conversion before enabling the strict Microsoft-account block.
- Verify `WamDefaultSet : NO` after removing the OS-level Microsoft identity (with `dsregcmd /status`).

#### ID-03 - Block Microsoft accounts at the OS level

With Local Group Policy Editor, open: `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`

Set: `Accounts: Block Microsoft accounts` to: `Users can't add or log on with Microsoft accounts`

Expected effective value: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser=3`

### 2.7 Settings-only and application-only controls

#### SET-01 - Cross-device Resume off

Open: `Settings > Apps > Resume` and set `Resume` to `Off`.

#### SET-02 - Windows Location services off

Open: `Settings > Privacy & security > Location` and set `Location services` to `Off`.

A forced Location Group Policy is optional if the goal is to prevent users from re-enabling it. The validated baseline used the Settings switch.

#### SET-03 - Office privacy and connected experiences

In Word, Excel, or PowerPoint: `File/Account > Account Privacy > Manage Settings`

- Keep the optional diagnostic and connected-experience controls at the maximally restricted state selected during the project.
- Preserve Office licensing and Click-to-Run security servicing.

## 3. Endpoint coverage verification

Every endpoint/pattern from the removed-or-blocked endpoint table is mapped below.

| Endpoint or pattern                                        | Canonical controls                                                 | Coverage verdict                | Notes                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------- |
| `v10.events.data.microsoft.com`                            | GPO-01 + SCM-02                                                    | Covered                         | Diagnostic event upload source disabled                                                     |
| `v20.events.data.microsoft.com`                            | GPO-01 + SCM-02                                                    | Covered                         | Same source family                                                                          |
| `browser.events.data.msn.com`                              | APP-01 + GPO-02 + GPO-03                                           | Covered                         | Start experiences package removed; content surfaces disabled                                |
| `settings-win.data.microsoft.com`                          | HOST-01                                                            | Covered                         | Local sinkhole; external connection should not occur                                        |
| `watson.events.data.microsoft.com`                         | GPO-12                                                             | Covered                         | WER upload disabled                                                                         |
| `client.wns.windows.com`                                   | GPO-05                                                             | Covered                         | Cloud notification network usage disabled                                                   |
| `activity.windows.com`                                     | GPO-04                                                             | Covered                         | Activity Feed and upload disabled                                                           |
| `enterprise.activity.windows.com`                          | GPO-04                                                             | Covered                         | Same policy family                                                                          |
| `cs.dds.microsoft.com`                                     | GPO-09 + GPO-10 + GPO-11 + SCM-01 + SCM-03 + ID-01 + ID-02 + ID-03 | Covered                         | Source-level shutdown; no permanent DDS firewall rule                                       |
| `graph.microsoft.com` from `CrossDeviceResume.exe`         | SET-01                                                             | Covered, source-specific        | Graph is not globally blocked                                                               |
| `inference.location.live.net`                              | SET-02                                                             | Covered                         | Windows Location off                                                                        |
| `agps.location.live.net`                                   | SET-02                                                             | Covered                         | Windows Location off                                                                        |
| `fd.api.iris.microsoft.com`                                | GPO-03 + HOST-02                                                   | Covered                         | Spotlight source disabled plus sinkhole                                                     |
| `assets.msn.com`                                           | GPO-02 + GPO-03 + APP-01                                           | Covered                         | Widgets/Spotlight/Start content removed                                                     |
| `arc.msn.com`                                              | GPO-02 + GPO-03 + APP-01                                           | Covered                         | Same source family                                                                          |
| `api.msn.com`                                              | GPO-02 + GPO-03 + APP-01                                           | Covered                         | Same source family                                                                          |
| `www.msn.com`                                              | GPO-02 + GPO-03 + APP-01                                           | Covered                         | Same source family                                                                          |
| `c.msn.com`                                                | GPO-02 + GPO-03 + APP-01                                           | Covered                         | Same source family                                                                          |
| `windows.msn.com`                                          | GPO-02 + GPO-03 + APP-01                                           | Covered                         | Same source family                                                                          |
| `e.clarity.ms`, `c.clarity.ms`, `www.clarity.ms`           | GPO-02 + GPO-03 + APP-01                                           | Covered by source removal       | Not individually sinkholed                                                                  |
| `sb.scorecardresearch.com`                                 | GPO-02 + GPO-03 + APP-01                                           | Covered by source removal       | Not individually sinkholed                                                                  |
| `www.bing.com` from Windows Search                         | GPO-06                                                             | Covered                         | Bing is not globally blocked for a browser the user intentionally opens                     |
| `www.msftconnecttest.com`                                  | GPO-07                                                             | Covered                         | NCSI active probe off                                                                       |
| `dns.msftncsi.com`                                         | GPO-07                                                             | Covered                         | NCSI active probe off                                                                       |
| `array*.prod.do.dsp.mp.microsoft.com`                      | GPO-14                                                             | Covered                         | Delivery Optimization Simple mode                                                           |
| `config.edge.skype.com`                                    | GPO-15 + GPO-16 + GPO-17                                           | Covered                         | Browser, WebView2, and updater ECS controls                                                 |
| `ic3.events.data.microsoft.com`                            | APP-02                                                             | Covered                         | Teams removed                                                                               |
| `teams.microsoft.com`                                      | APP-02                                                             | Covered                         | Teams removed                                                                               |
| `teams.live.com`                                           | APP-02                                                             | Covered                         | Teams removed                                                                               |
| `*.trouter.skype.com`                                      | APP-02                                                             | Covered                         | Teams removed                                                                               |
| `login.microsoftonline.com` idle Teams/work-account source | APP-02 + ID-01 + GPO-11                                            | Covered for the unwanted source | Hostname is not globally blocked and can be used by an app the user deliberately signs into |

Endpoint coverage result: all 32 endpoint rows are assigned to a canonical control. Shared endpoints are explicitly marked as source-specific rather than falsely described as globally blocked.

## 4. Disabled, stopped, or removed component coverage verification

| Component or state                                          | Canonical controls | Coverage verdict                        | Notes                                                                  |
| ----------------------------------------------------------- | ------------------ | --------------------------------------- | ---------------------------------------------------------------------- |
| CDPSvc stopped and disabled                                 | SCM-01             | Covered                                 | Service Control Manager owns state                                     |
| DiagTrack stopped and disabled                              | SCM-02             | Covered                                 | Service Control Manager owns state                                     |
| CDPUserSvc disabled; `UserServiceFlags=0`                   | SCM-03             | Covered with service-template exception | Exact flags require service-template metadata handling                 |
| Microsoft.StartExperiencesApp removed and deprovisioned     | APP-01             | Covered                                 | AppX state, not GPO                                                    |
| Microsoft Teams uninstalled                                 | APP-02             | Covered                                 | Installed-app/MSI/AppX state                                           |
| Microsoft Edge browser uninstalled                          | APP-03             | Covered where supported                 | WebView2 intentionally kept                                            |
| Widgets disabled                                            | GPO-02             | Covered                                 | Local GPO                                                              |
| Spotlight and consumer content disabled                     | GPO-03             | Covered                                 | Local GPO; value-2 correction documented                               |
| Activity Feed disabled                                      | GPO-04             | Covered                                 | Local GPO                                                              |
| WNS cloud notifications disabled                            | GPO-05             | Covered                                 | Local GPO                                                              |
| Windows web search/Bing integration disabled                | GPO-06             | Covered                                 | Local GPO plus User Registry.pol record                                |
| Sync your settings disabled                                 | GPO-09             | Covered                                 | Master policy required; category policies optional defense in depth    |
| CDP/MMX cross-device features disabled                      | GPO-10             | Covered                                 | Local GPO                                                              |
| Resume off                                                  | SET-01             | Covered                                 | Settings-only feature                                                  |
| Workplace registration disconnected and future join blocked | ID-01 + GPO-11     | Covered                                 | Existing identity removal plus preventive policy                       |
| OS Microsoft account replaced by local account and blocked  | ID-02 + ID-03      | Covered                                 | Identity subsystem and Security Options                                |
| Windows Error Reporting upload disabled                     | GPO-12             | Covered                                 | Task/process may still run without transmitting                        |
| Windows Location services off                               | SET-02             | Covered                                 | Settings-only baseline                                                 |
| NCSI active probes disabled                                 | GPO-07             | Covered                                 | Local GPO                                                              |
| Windows CEIP disabled                                       | GPO-08             | Covered                                 | Local GPO                                                              |
| Help "Did you know?" online content disabled                | GPO-08             | Covered                                 | Local GPO                                                              |
| Windows Messenger CEIP disabled                             | GPO-08             | Covered                                 | Local GPO                                                              |
| Explorer SmartScreen disabled                               | GPO-13             | Covered                                 | Defender Network Protection remains on                                 |
| Defender antivirus, real-time, behavior, and IOAV preserved | DEF-01             | Covered                                 | Engine-health preservation; other Defender preferences are not audited |
| Edge ECS disabled                                           | GPO-15             | Covered                                 | Vendor ADMX/LGPO                                                       |
| WebView2 ECS disabled                                       | GPO-16             | Covered                                 | Vendor ADMX/LGPO                                                       |
| Edge Update ECS disabled                                    | GPO-17             | Covered                                 | Vendor ADMX/LGPO                                                       |
| Delivery Optimization coordination/peering reduced          | GPO-14             | Covered                                 | Simple mode 99                                                         |
| Visual Studio SQM disabled                                  | GPO-18             | Covered                                 | Registry.pol via ADMX or LGPO text                                     |
| VS Code telemetry disabled                                  | APP-04             | Covered                                 | Application setting                                                    |
| VS Code experiments disabled                                | APP-04             | Covered                                 | Application setting                                                    |
| Office optional privacy/connected experiences restricted    | SET-03             | Covered                                 | Office UI/policy; required serviceability remains                      |

Component coverage result: every component or state from the prior table is assigned to an owning control surface. The only structural exceptions are the CDP user-service metadata field and package removals that are not exposed by a stock Settings UI.

## 5. Audit of Windows-Privacy-Audit.ps1

To run, open Powershell with Administrator priviledges and in the window, enter:

```ps1
Set-ExecutionPolicy -Scope Process Bypass -Force

Unblock-File -LiteralPath  .\Windows-Privacy-Audit.ps1

.\Windows-Privacy-Audit.ps1
```

### 5.1 What the script actually audits

The PowerShell audit verifies a mix of registry, service, application, identity, preservation, and cleanup states. It does not observe network traffic or prove that an endpoint emitted zero packets.

For example:

- The script can verify `AllowTelemetry = 0` and `DiagTrack` disabled.
- It cannot prove that `v10.events.data.microsoft.com` emitted zero packets without observing network traffic.

A manual audit's steps are:

1. Enable WFP 5156 and process-creation 4688 auditing temporarily.
2. Cold boot offline.
3. Start Wireshark.
4. Reconnect the network.
5. Idle for 25-30 minutes.
6. Correlate endpoint, destination, source port, executable, and PID.
7. Disable temporary auditing afterward.

### 5.2 Fully automated effective-state checks already present

The script currently checks:

- DiagTrack startup and running state.
- CDPSvc startup and running state.
- CDPUserSvc `Start` and `UserServiceFlags`.
- `AllowTelemetry`.
- Activity Feed, publishing, and uploading values.
- `EnableCdp` and `EnableMmx`.
- The recorded CloudContent/Spotlight values.
- Widgets.
- WNS network usage.
- `BlockAADWorkplaceJoin`.
- The Microsoft-account Security Options effective registry value.
- `DisableSearchBoxSuggestions`.
- `DisableWebSearch` and `ConnectedSearchUseWeb`.
- The master and per-category Settings Sync registry values encoded in the script.
- NCSI `NoActiveProbe`.
- Windows CEIP `CEIPEnable`.
- Help headlines and Windows Messenger CEIP values.
- Delivery Optimization mode 99.
- Edge, WebView2, and Edge Update ECS policy values.
- WER effective registry value.
- Explorer SmartScreen effective registry value.
- Defender antivirus, real-time protection, behavior monitoring, and IOAV engine health.
- Both IPv4 and IPv6 hosts entries for both sinkholed endpoints.
- Microsoft.StartExperiencesApp installed and provisioned package absence.
- Microsoft Teams installed-client absence checks.
- Microsoft Edge browser absence where supported and WebView2 Runtime presence.
- Visual Studio SQM effective value.
- VS Code telemetry and experiments when the settings file exists.
- The current interactive sign-in source and the `dsregcmd` fields encoded in the script.
- Absence of the old DDS firewall rule and Dynamic Keyword Address.
- Temporary WFP/process-creation auditing is off.

The current script checks effective registry values only. It does not verify that registry-policy values originated in Local Group Policy or `Registry.pol`.

### 5.3 Manual or owner-UI checks that are intentionally not fully automated

| Manual item                             | Reason                                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Resume is Off                           | The validated control is the Settings app state; there is no need to guess an unstable private registry representation.                   |
| Location services is Off                | The script does not inspect build-dependent backing state; the Settings UI remains authoritative.                                         |
| Office privacy controls                 | The original state was configured in Office's privacy UI rather than as a complete Office policy set.                                     |
| Work/school account disconnected        | `dsregcmd` gives strong verification, but the account list in Settings remains the clearest human check.                                  |
| OS login converted to local account     | This can be automated, but the current script does not do so and the account conversion itself should remain an explicit identity action. |
| Package removal when no UI is available | `Microsoft.StartExperiencesApp` removal may require AppX tooling.                                                                         |
| Edge uninstallation availability        | Whether the Uninstall action exists depends on the Windows build and region.                                                              |
| Automatic root-certificate updates      | Required by the manifest but not currently audited; verify `DisableRootAutoUpdate` is absent or `0`.                                      |

## 6. Final audit verdict

The control paths and semantics in this document were checked against current Microsoft documentation, including:

- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) and [LGPO.exe tool guidance](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/lgpo-exe---local-group-policy-object-utility-v1-0/701045).
- [Windows Spotlight configuration](https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight) and [Experience Policy CSP mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience).
- [Privacy Policy CSP mappings for Activity Feed and user activities](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy).
- [ADMX Group Policy CSP mappings for CDP and MMX](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-grouppolicy).
- [Notifications Policy CSP for WNS network-use policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-notifications).
- [Search Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search) and [Windows privacy connection-management guidance](https://learn.microsoft.com/en-gb/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services).
- [SettingsSync ADMX Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-settingsync) and [Windows Backup policy settings](https://learn.microsoft.com/en-us/windows/configuration/windows-backup/policy-settings).
- [ErrorReporting Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-errorreporting).
- [Microsoft Edge Experimentation and Configuration Service policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/experimentationandconfigurationservicecontrol), [Microsoft Edge WebView2 policy documentation](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-webview-policies), and [Microsoft Edge Update policy documentation](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies).
- [Microsoft 365 Apps privacy-control documentation](https://learn.microsoft.com/en-us/microsoft-365-apps/privacy/manage-privacy-controls).
- [Delivery Optimization Simple mode documentation](https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference).
