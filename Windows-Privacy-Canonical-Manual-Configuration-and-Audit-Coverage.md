# Windows Privacy Hardening: Canonical Manual Configuration and Audit Coverage

Snapshot date: 2026-08-30

This document converts the August 2026 hardening project into a reusable configuration model. It maps every removed or blocked endpoint and every disabled, stopped, or removed Windows/application component from `Windows-Privacy-Network-Manifest.md` to the correct control surface.

It also audits the current `Windows-Privacy-Audit.ps1` and states exactly what that script verifies, what it only partially verifies, and what it does not verify.

## 1. Canonical configuration model

Use the control surface that owns the setting. Do not treat the live registry as the universal source of truth.

| Configuration type | Canonical owner | Preferred manual method |
|---|---|---|
| Administrative Template policy | Local Group Policy object and `Registry.pol` | `gpedit.msc`, or Microsoft `LGPO.exe` when a friendly ADMX entry is unavailable |
| Security Options policy | Local security-policy database | `secpol.msc` or the Security Settings branch of Local Group Policy |
| Windows service state | Service Control Manager | `services.msc` or `sc.exe` |
| Microsoft Defender state | Defender configuration provider | Windows Security, Defender Group Policy, or supported `Set-MpPreference` cmdlets |
| Hostname sinkhole | Hosts file | Edit `%SystemRoot%\System32\drivers\etc\hosts` as administrator |
| Removed application/package | AppX, MSI, or application installation state | Settings > Apps when exposed; otherwise the appropriate AppX/MSI removal mechanism |
| Account and device identity | Windows identity subsystem | Settings > Accounts, `secpol.msc`, and `dsregcmd` verification |
| Settings-only or application-only feature | Owning Settings/app UI | Windows Settings, Office privacy UI, or application settings |

Microsoft's LGPO utility can import and apply Registry Policy files and LGPO text, and can export the current Local GPO. That is the clean way to automate Local Group Policy while keeping `Registry.pol` as the authoritative store.

### Important exceptions

1. Some settings do not have a stock Group Policy UI even though they can be represented as registry policy. Use `LGPO.exe` to put those records into `Registry.pol` rather than writing the live policy registry directly.
2. `CDPUserSvc\UserServiceFlags` is service-template metadata, not an ordinary Administrative Template policy and not a normal Services.msc property. Exact parity with the original machine may require a manual Registry Editor change under the service template. This is the narrow exception to the service-only rule.
3. `Microsoft.StartExperiencesApp` might not be exposed in Settings > Installed apps. Exact package removal may require AppX tooling. There is no honest GPO substitute for an application that was actually removed.
4. Edge browser uninstallation is build, region, and servicing-state dependent. Do not remove Microsoft Edge WebView2 Runtime; applications depend on it and it must continue receiving security updates.
5. The Defender Core telemetry, Defender Core ECS, gradual-release, and Network Protection performance-telemetry controls may not appear in the stock Local Group Policy editor. Supported Defender cmdlets or MDM policy are the canonical controls for those items.

## 2. Canonical control catalog

Each control has an ID. The endpoint and component coverage tables later in this document reference these IDs.

### 2.1 Local Group Policy and Registry.pol controls

#### GPO-01 - Windows diagnostic data

- Open: `Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds`.
- Configure `Allow Diagnostic Data` to the Enterprise option that represents diagnostic data off / Security / value 0. Older ADMX versions may call this policy `Allow Telemetry`.
- Expected effective value: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry = 0`.
- This policy works with SCM-01, because the `DiagTrack` service was also disabled.

#### GPO-02 - Widgets

- Open: `Computer Configuration > Administrative Templates > Windows Components > Widgets`.
- Set `Allow widgets` to `Disabled`.
- Expected effective value: `HKLM\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests = 0`.

#### GPO-03 - Windows Spotlight and consumer content

User policies under:

`User Configuration > Administrative Templates > Windows Components > Cloud Content`

Set these to `Enabled`:

- `Turn off all Windows spotlight features`
- `Turn off Spotlight collection on Desktop`
- `Do not use diagnostic data for tailored experiences`
- `Do not suggest third-party content in Windows spotlight`
- `Turn off Windows Spotlight on Action Center`
- `Turn off Windows Spotlight on Settings`
- `Turn off the Windows Welcome Experience` / `Turn off Windows Spotlight Windows Welcome Experience`

For the lock screen policy:

- Open `Configure Windows spotlight on lock screen`.
- Set the policy to `Disabled`, rather than enabling it with an option value.

Computer policies under:

`Computer Configuration > Administrative Templates > Windows Components > Cloud Content`

Set these to `Enabled`:

- `Turn off Microsoft consumer experiences`
- `Turn off cloud optimized content`
- `Turn off cloud consumer account state content`

For values that have no friendly ADMX entry on a particular build, use LGPO text to place the intended record in the correct User or Machine `Registry.pol`.

Important correction for the reusable baseline:

- Do not make `ConfigureWindowsSpotlight = 2` a required hardening invariant.
- Microsoft's current policy mapping defines value 2 as Spotlight always enabled and not user-disableable.
- The primary hardening invariant is `Turn off all Windows spotlight features = Enabled`, and the lock-screen Spotlight policy should be `Disabled` if it is configured.
- The old audit script currently expects `ConfigureWindowsSpotlight = 2`; this is identified later as a script problem.

#### GPO-04 - Activity Feed and user-activity upload

Open:

`Computer Configuration > Administrative Templates > System > OS Policies`

Set these to `Disabled`:

- `Enable Activity Feed`
- `Allow publishing of User Activities`
- `Allow upload of User Activities`

Expected effective values under `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`:

- `EnableActivityFeed = 0`
- `PublishUserActivities = 0`
- `UploadUserActivities = 0`

#### GPO-05 - Windows Push Notification Service network use

Open:

`Computer Configuration > Administrative Templates > Start Menu and Taskbar > Notifications`

- Set `Turn off notifications network usage` to `Enabled`.
- Expected effective value: `NoCloudApplicationNotification = 1`.

#### GPO-06 - Windows Search web integration

Open:

`Computer Configuration > Administrative Templates > Windows Components > Search`

Set these to `Enabled`:

- `Do not allow web search`
- `Don't search the web or display web results in Search`

Expected effective values:

- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\DisableWebSearch = 1`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb = 0`

Also preserve the per-user Start/Search suggestions block:

- User policy record: `HKCU\Software\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions = 1`.
- If no friendly ADMX item is available, import it into the User `Registry.pol` with `LGPO.exe`.

#### GPO-07 - NCSI active connectivity probes

Open:

`Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings`

- Set `Turn off Windows Network Connectivity Status Indicator active tests` to `Enabled`.
- Expected effective value: `NoActiveProbe = 1`.

#### GPO-08 - CEIP and Internet Communication content

In the same Internet Communication settings folder, set these to `Enabled`:

- `Turn off Windows Customer Experience Improvement Program`
- `Turn off Help and Support Center "Did you know?" content`
- `Turn off Windows Messenger Customer Experience Improvement Program`

The Windows CEIP effective baseline includes:

- `HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable = 0`.

#### GPO-09 - Windows settings synchronization

Open:

`Computer Configuration > Administrative Templates > Windows Components > Sync your settings`

- Set `Do not sync` to `Enabled`.
- The master policy is the required baseline.
- Preserve the individual `Do not sync ...` policies that were also enabled as defense in depth, including passwords, personalization, browser/app settings, language preferences, accessibility, and other Windows settings where those policies are available.

The master policy should populate the `SettingSync` policy area, including `DisableSettingSync`.

#### GPO-10 - Cross-device experiences and Phone-PC linking

Open:

`Computer Configuration > Administrative Templates > System > Group Policy`

Set these to `Disabled`:

- `Continue experiences on this device`
- `Phone-PC linking on this device`

Expected effective values:

- `EnableCdp = 0`
- `EnableMmx = 0`

A reboot is required for these policies.

#### GPO-11 - Block Workplace Join

Preferred policy:

- If the ADMX entry exists, open `Computer Configuration > Administrative Templates > Windows Components > Workplace Join` and enable the policy that blocks Microsoft Entra/AAD Workplace Join.
- Required effective value: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\BlockAADWorkplaceJoin = 1`.
- If no friendly ADMX entry exists, import this Machine policy record with `LGPO.exe`.

This policy supplements ID-01; it does not replace disconnecting an existing work or school registration.

#### GPO-12 - Windows Error Reporting

Open:

`Computer Configuration > Administrative Templates > Windows Components > Windows Error Reporting`

- Set `Disable Windows Error Reporting` to `Enabled`.
- Expected effective value: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled = 1`.

The scheduled task and `wermgr.exe` can still launch. Success means no external Watson/WER upload, not that the process is forbidden from existing.

#### GPO-13 - Explorer SmartScreen

Open:

`Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer`

- Set `Configure Windows Defender SmartScreen` to `Disabled`.

This disables the Explorer/application-reputation surface. It does not disable Defender Network Protection, which remains enabled under DEF-08.

#### GPO-14 - Delivery Optimization Simple mode

Open:

`Computer Configuration > Administrative Templates > Windows Components > Delivery Optimization`

- Configure `Download Mode` as `Simple (99)`.
- This disables Delivery Optimization cloud coordination and peer caching while preserving direct update downloads.

#### GPO-15 - Microsoft Edge ECS

Install the current Microsoft Edge administrative templates if needed.

Open:

`Administrative Templates > Microsoft Edge`

- Configure `Control communication with the Experimentation and Configuration Service` as `RestrictedMode (0)`.

Expected policy value:

- `SOFTWARE\Policies\Microsoft\Edge\ExperimentationAndConfigurationServiceControl = 0`.

#### GPO-16 - Microsoft Edge WebView2 ECS

Install the current WebView2 administrative template if needed.

Open:

`Administrative Templates > Microsoft Edge WebView2`

- Configure `Control communication with the Experimentation and Configuration Service` as `RestrictedMode (0)`.

Expected policy value:

- `SOFTWARE\Policies\Microsoft\Edge\WebView2\ExperimentationAndConfigurationServiceControl = 0`.

#### GPO-17 - Microsoft Edge Update ECS

Install the current Microsoft Edge Update administrative template if needed.

Open:

`Administrative Templates > Microsoft Edge Update > Microsoft Edge Update`

- Set `Control updater's communication with the Experimentation and Configuration Service` to `Disabled`.
- Expected policy value: `UpdaterExperimentationAndConfigurationServiceControl = 0`.

Do not disable WebView2 Runtime updates themselves.

#### GPO-18 - Visual Studio SQM

- Desired policy record: `HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\SQM\OptIn = 0`.
- If a Visual Studio administrative template exposes this setting, configure it there.
- Otherwise import the Machine policy record through LGPO text so it lives in `Registry.pol`.
- The policy is inert if full Visual Studio is not installed, but it is still a useful reusable baseline.

#### GPO-19 - Windows Update remains enabled

Open:

`Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage end user experience`

- Leave `Configure Automatic Updates` as `Not Configured`.

This is a preserved-security setting, not a privacy kill.

#### GPO-20 - Automatic root-certificate updates remain enabled

Open:

`Computer Configuration > Administrative Templates > System > Internet Communication Management > Internet Communication settings`

- Leave `Turn off Automatic Root Certificates Update` as `Disabled` or `Not Configured`.
- `DisableRootAutoUpdate` should be absent or 0.

This is a preserved-security setting.

### 2.2 Service Control Manager controls

#### SCM-01 - DiagTrack

Open `services.msc`:

- Service: `Connected User Experiences and Telemetry`
- Service name: `DiagTrack`
- Stop the service.
- Set Startup type to `Disabled`.

#### SCM-02 - CDPSvc

Open `services.msc`:

- Service: `Connected Devices Platform Service`
- Service name: `CDPSvc`
- Stop the service.
- Set Startup type to `Disabled`.

#### SCM-03 - CDPUserSvc service template

- Disable the base `CDPUserSvc` service template through Service Control Manager where supported, for example with `sc.exe config CDPUserSvc start= disabled` from an elevated Command Prompt.
- Verify the template's Start value is 4.
- Exact parity with the original system also used `UserServiceFlags = 0`.
- Because `UserServiceFlags` is not exposed by Services.msc or normal `sc.exe` configuration, use Registry Editor only for this service-template metadata if the value is required.

### 2.3 Microsoft Defender controls

Use Windows Security, Defender Group Policy, or the supported Defender configuration cmdlets. Do not implement these by inventing generic registry edits.

#### DEF-01 - Defender Core telemetry off

- Desired: `DisableCoreServiceTelemetry = True`.
- Supported command: `Set-MpPreference -DisableCoreServiceTelemetry $true`.

#### DEF-02 - Defender Core ECS integration off

- Desired: `DisableCoreServiceECSIntegration = True`.
- Supported command: `Set-MpPreference -DisableCoreServiceECSIntegration $true`.

#### DEF-03 - Defender gradual release off

- Desired: `DisableGradualRelease = True`.
- Supported command: `Set-MpPreference -DisableGradualRelease $true`.

#### DEF-04 - Network Protection performance telemetry off

- Desired: `DisableNetworkProtectionPerfTelemetry = True`.
- Supported command: `Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true`.

#### DEF-05 - Defender MAPS/cloud protection on

- Desired: `MAPSReporting = 2`.
- Use Defender MAPS policy or the supported Defender command.
- Windows Security's `Cloud-delivered protection` should remain On.

#### DEF-06 - Safe sample submission

- Desired: `SubmitSamplesConsent = 1` (`SendSafeSamples`).
- Use Defender MAPS Group Policy or Defender command.

#### DEF-07 - Block at First Sight on

- In Defender MAPS Group Policy, configure the Block at First Sight feature as enabled.
- Desired effective state: `DisableBlockAtFirstSeen = False`.

#### DEF-08 - Network Protection on

- Enable Defender Network Protection through Defender policy or the supported Defender command.
- Desired: `EnableNetworkProtection = 1`.

### 2.4 Hosts-file controls

Edit `%SystemRoot%\System32\drivers\etc\hosts` as administrator.

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

#### ID-01 - Disconnect work or school registration

Open:

`Settings > Accounts > Access work or school`

- Select each unwanted connected work/school account.
- Choose `Disconnect`.
- Verify `WorkplaceJoined : NO` with `dsregcmd /status`.

#### ID-02 - Use a local Windows account

Open:

`Settings > Accounts > Your info`

- Choose `Sign in with a local account instead`.
- Complete the conversion before enabling the strict Microsoft-account block.
- Verify `WamDefaultSet : NO` after removing the OS-level Microsoft identity.

#### ID-03 - Block Microsoft accounts at the OS level

Open:

`Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`

Set:

`Accounts: Block Microsoft accounts`

To:

`Users can't add or log on with Microsoft accounts`

This is a Security Options policy and is not an Administrative Template `Registry.pol` item.

### 2.7 Settings-only and application-only controls

#### SET-01 - Cross-device Resume off

Open:

`Settings > Apps > Resume`

- Set Resume to `Off`.

#### SET-02 - Windows Location services off

Open:

`Settings > Privacy & security > Location`

- Set `Location services` to `Off`.

A forced Location Group Policy is optional if the goal is to prevent users from re-enabling it. The validated baseline used the Settings switch.

#### SET-03 - Office privacy and connected experiences

In Word, Excel, or PowerPoint:

`File/Account > Account Privacy > Manage Settings`

- Keep the optional diagnostic and connected-experience controls at the maximally restricted state selected during the project.
- Preserve Office licensing and Click-to-Run security servicing.

## 3. Endpoint coverage verification

Every endpoint/pattern from the removed-or-blocked endpoint table is mapped below.

| Endpoint or pattern | Canonical controls | Coverage verdict | Notes |
|---|---|---|---|
| `v10.events.data.microsoft.com` | GPO-01 + SCM-01 | Covered | Diagnostic event upload source disabled |
| `v20.events.data.microsoft.com` | GPO-01 + SCM-01 | Covered | Same source family |
| `browser.events.data.msn.com` | APP-01 + GPO-02 + GPO-03 | Covered | Start experiences package removed; content surfaces disabled |
| `mobile.events.data.microsoft.com` from Defender Core | DEF-01 | Covered, conditional hostname | Office Click-to-Run may still legitimately use the same hostname |
| `settings-win.data.microsoft.com` | HOST-01 | Covered | Local sinkhole; external connection should not occur |
| `watson.events.data.microsoft.com` | GPO-12 | Covered | WER upload disabled |
| `client.wns.windows.com` | GPO-05 | Covered | Cloud notification network usage disabled |
| `activity.windows.com` | GPO-04 | Covered | Activity Feed and upload disabled |
| `enterprise.activity.windows.com` | GPO-04 | Covered | Same policy family |
| `cs.dds.microsoft.com` | GPO-09 + GPO-10 + GPO-11 + SCM-02 + SCM-03 + ID-01 + ID-02 + ID-03 | Covered | Source-level shutdown; no permanent DDS firewall rule |
| `graph.microsoft.com` from `CrossDeviceResume.exe` | SET-01 | Covered, source-specific | Graph is not globally blocked |
| `inference.location.live.net` | SET-02 | Covered | Windows Location off |
| `agps.location.live.net` | SET-02 | Covered | Windows Location off |
| `fd.api.iris.microsoft.com` | GPO-03 + HOST-02 | Covered | Spotlight source disabled plus sinkhole |
| `assets.msn.com` | GPO-02 + GPO-03 + APP-01 | Covered | Widgets/Spotlight/Start content removed |
| `arc.msn.com` | GPO-02 + GPO-03 + APP-01 | Covered | Same source family |
| `api.msn.com` | GPO-02 + GPO-03 + APP-01 | Covered | Same source family |
| `www.msn.com` | GPO-02 + GPO-03 + APP-01 | Covered | Same source family |
| `c.msn.com` | GPO-02 + GPO-03 + APP-01 | Covered | Same source family |
| `windows.msn.com` | GPO-02 + GPO-03 + APP-01 | Covered | Same source family |
| `e.clarity.ms`, `c.clarity.ms`, `www.clarity.ms` | GPO-02 + GPO-03 + APP-01 | Covered by source removal | Not individually sinkholed |
| `sb.scorecardresearch.com` | GPO-02 + GPO-03 + APP-01 | Covered by source removal | Not individually sinkholed |
| `www.bing.com` from Windows Search | GPO-06 | Covered | Bing is not globally blocked for a browser the user intentionally opens |
| `www.msftconnecttest.com` | GPO-07 | Covered | NCSI active probe off |
| `dns.msftncsi.com` | GPO-07 | Covered | NCSI active probe off |
| `array*.prod.do.dsp.mp.microsoft.com` | GPO-14 | Covered | Delivery Optimization Simple mode |
| `config.edge.skype.com` | GPO-15 + GPO-16 + GPO-17 | Covered | Browser, WebView2, and updater ECS controls |
| `ic3.events.data.microsoft.com` | APP-02 | Covered | Teams removed |
| `teams.microsoft.com` | APP-02 | Covered | Teams removed |
| `teams.live.com` | APP-02 | Covered | Teams removed |
| `*.trouter.skype.com` | APP-02 | Covered | Teams removed |
| `login.microsoftonline.com` idle Teams/work-account source | APP-02 + ID-01 + GPO-11 | Covered for the unwanted source | Hostname is not globally blocked and can be used by an app the user deliberately signs into |

Endpoint coverage result: all 32 endpoint rows are assigned to a canonical control. Shared endpoints are explicitly marked as source-specific rather than falsely described as globally blocked.

## 4. Disabled, stopped, or removed component coverage verification

| Component or state | Canonical controls | Coverage verdict | Notes |
|---|---|---|---|
| DiagTrack stopped and disabled | SCM-01 | Covered | Service Control Manager owns state |
| CDPSvc stopped and disabled | SCM-02 | Covered | Service Control Manager owns state |
| CDPUserSvc disabled; `UserServiceFlags=0` | SCM-03 | Covered with service-template exception | Exact flags require service-template metadata handling |
| Microsoft.StartExperiencesApp removed and deprovisioned | APP-01 | Covered | AppX state, not GPO |
| Microsoft Teams uninstalled | APP-02 | Covered | Installed-app/MSI/AppX state |
| Microsoft Edge browser uninstalled | APP-03 | Covered where supported | WebView2 intentionally kept |
| Widgets disabled | GPO-02 | Covered | Local GPO |
| Spotlight and consumer content disabled | GPO-03 | Covered | Local GPO; value-2 correction documented |
| Activity Feed disabled | GPO-04 | Covered | Local GPO |
| WNS cloud notifications disabled | GPO-05 | Covered | Local GPO |
| Windows web search/Bing integration disabled | GPO-06 | Covered | Local GPO plus User Registry.pol record |
| Sync your settings disabled | GPO-09 | Covered | Master policy required; category policies optional defense in depth |
| CDP/MMX cross-device features disabled | GPO-10 | Covered | Local GPO |
| Resume off | SET-01 | Covered | Settings-only feature |
| Workplace registration disconnected and future join blocked | ID-01 + GPO-11 | Covered | Existing identity removal plus preventive policy |
| OS Microsoft account replaced by local account and blocked | ID-02 + ID-03 | Covered | Identity subsystem and Security Options |
| Windows Error Reporting upload disabled | GPO-12 | Covered | Task/process may still run without transmitting |
| Windows Location services off | SET-02 | Covered | Settings-only baseline |
| NCSI active probes disabled | GPO-07 | Covered | Local GPO |
| Windows CEIP disabled | GPO-08 | Covered | Local GPO |
| Help "Did you know?" online content disabled | GPO-08 | Covered | Local GPO |
| Windows Messenger CEIP disabled | GPO-08 | Covered | Local GPO |
| Explorer SmartScreen disabled | GPO-13 | Covered | Defender Network Protection remains on |
| Defender Core telemetry disabled | DEF-01 | Covered | Defender provider |
| Defender Core ECS disabled | DEF-02 | Covered | Defender provider |
| Defender gradual release disabled | DEF-03 | Covered | Defender provider |
| Defender Network Protection performance telemetry disabled | DEF-04 | Covered | Defender provider |
| Defender MAPS/cloud protection preserved | DEF-05 | Covered | Security-preservation control |
| Safe sample submission preserved | DEF-06 | Covered | Security-preservation control |
| Block at First Sight preserved | DEF-07 | Covered | Security-preservation control |
| Network Protection preserved | DEF-08 | Covered | Security-preservation control |
| Edge ECS disabled | GPO-15 | Covered | Vendor ADMX/LGPO |
| WebView2 ECS disabled | GPO-16 | Covered | Vendor ADMX/LGPO |
| Edge Update ECS disabled | GPO-17 | Covered | Vendor ADMX/LGPO |
| Delivery Optimization coordination/peering reduced | GPO-14 | Covered | Simple mode 99 |
| Visual Studio SQM disabled | GPO-18 | Covered | Registry.pol via ADMX or LGPO text |
| VS Code telemetry disabled | APP-04 | Covered | Application setting |
| VS Code experiments disabled | APP-04 | Covered | Application setting |
| Office optional privacy/connected experiences restricted | SET-03 | Covered | Office UI/policy; required serviceability remains |
| Windows Update preserved | GPO-19 | Covered | Intentionally Not Configured |
| Root-certificate updates preserved | GPO-20 | Covered | Intentionally not turned off |

Component coverage result: every component or state from the prior table is assigned to an owning control surface. The only structural exceptions are the CDP user-service metadata field and package removals that are not exposed by a stock Settings UI.

## 5. Audit of Windows-Privacy-Audit.ps1

### 5.1 What the script actually audits

The current script is an effective-state audit. It reads service status, live registry values, Defender state, hosts entries, package state, and `dsregcmd` output.

It does not inspect the binary `Registry.pol` files and does not prove that a value was created through the Local GPO rather than written directly into the live registry.

That distinction is now important because this document adopts `Registry.pol` as the canonical owner for Administrative Template settings.

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
- NCSI `NoActiveProbe`.
- Windows CEIP `CEIPEnable`.
- Delivery Optimization mode 99.
- Edge, WebView2, and Edge Update ECS policy values.
- WER effective registry value.
- Explorer SmartScreen effective registry value.
- A likely Location consent-store value.
- Automatic root-certificate updates remain enabled.
- All Defender privacy/security settings used in the project.
- Defender engine health.
- Both IPv4 and IPv6 hosts entries for both sinkholed endpoints.
- Microsoft.StartExperiencesApp installed and provisioned package absence.
- Visual Studio SQM effective value.
- VS Code telemetry and experiments when the settings file exists.
- `dsregcmd` identity/join state.
- Absence of the old DDS firewall rule and Dynamic Keyword Address.
- Temporary WFP/process-creation auditing is off.

### 5.3 Automatable items the script does not currently check

These are not manual-only. The current script omits them even though they can be audited automatically.

| Missing automated check | Why it matters |
|---|---|
| Actual Local GPO / `Registry.pol` provenance | Every GPO-backed check reads only the effective registry. The script can pass while `gpedit.msc` still says Not Configured. |
| `DisableWebSearch = 1` | One of the two main Windows Search web policies is not checked. |
| `ConnectedSearchUseWeb = 0` | The second main Windows Search web policy is not checked. |
| `DisableSettingSync` and the selected per-category SettingSync values | The script only prints Sync as a manual reminder. It does not inspect the effective SettingSync policy. |
| Microsoft Teams absence | Teams-derived endpoints can return if Teams is reinstalled. The script does not check AppX/MSI Teams state. |
| Microsoft Edge browser absence | The script does not distinguish the removed Edge browser from the intentionally retained WebView2 Runtime. |
| Help and Support Center "Did you know?" policy | This configured Internet Communication policy is not checked. |
| Windows Messenger CEIP policy | This configured Internet Communication policy is not checked. |
| Current interactive Windows account is local | `dsregcmd` proves no Entra/Workplace registration and no WAM default, but it does not by itself prove the logged-in account is a local SAM account. |
| Windows Update `Configure Automatic Updates` is Not Configured | The script prints this as a manual check but does not inspect Local GPO or the effective Windows Update policy state. |
| VS Code settings file missing | The script silently skips both VS Code checks if `settings.json` is absent instead of reporting a CHECK result. |
| Full Visual Studio product absence | The script checks SQM policy but not whether Visual Studio Community has been reinstalled. This was not required for endpoint coverage, but it is useful historical context. |

### 5.4 Manual or owner-UI checks that are intentionally not fully automated

| Manual item | Reason |
|---|---|
| Resume is Off | The validated control is the Settings app state; there is no need to guess an unstable private registry representation. |
| Location services is Off | The script checks a likely consent-store value, but the Settings UI remains authoritative across build changes. |
| Office privacy controls | The original state was configured in Office's privacy UI rather than as a complete Office policy set. |
| Work/school account disconnected | `dsregcmd` gives strong verification, but the account list in Settings remains the clearest human check. |
| OS login converted to local account | This can be automated, but the current script does not do so and the account conversion itself should remain an explicit identity action. |
| Package removal when no UI is available | `Microsoft.StartExperiencesApp` removal may require AppX tooling. |
| Edge uninstallation availability | Whether the Uninstall action exists depends on the Windows build and region. |

### 5.5 Endpoint absence is not a static-script property

The PowerShell audit cannot prove that an endpoint is absent from the wire. It can only verify the controls expected to suppress it.

For example:

- The script can verify `AllowTelemetry = 0` and `DiagTrack` disabled.
- It cannot prove that `v10.events.data.microsoft.com` emitted zero packets without observing network traffic.

The same limitation applies to every endpoint row. The correct wire-level audit remains:

1. Enable WFP 5156 and process-creation 4688 auditing temporarily.
2. Cold boot offline.
3. Start Wireshark.
4. Reconnect the network.
5. Idle for 25-30 minutes.
6. Correlate endpoint, destination, source port, executable, and PID.
7. Disable temporary auditing afterward.

### 5.6 Spotlight audit defect in the current script

The script currently treats this observed value as required:

`ConfigureWindowsSpotlight = 2`

That should not be considered a reusable privacy-hardening invariant. Current Microsoft policy documentation maps value 2 to Spotlight always enabled and not user-disableable.

A cleaner future audit should:

- Require `DisableWindowsSpotlightFeatures = 1`.
- Require the individual Spotlight-disable policies selected in the baseline.
- Treat `ConfigureWindowsSpotlight` as either 0 or the result of the GPO being set to Disabled, depending on the active ADMX representation.
- Not require value 2.

The existing script can therefore produce a misleading result for a cleaner Local GPO configuration.

## 6. Final audit verdict

### Manual-configuration coverage

PASS: Every endpoint and every component from the two prior tables has an assigned canonical control surface.

The reusable configuration is cleanly divided among:

- Local GPO/Registry.pol
- Local security policy
- Service Control Manager
- Defender configuration
- Hosts file
- AppX/MSI/application state
- Windows identity state
- Settings/application UI

### Windows-Privacy-Audit.ps1 coverage

PARTIAL: The script covers most effective-state controls, but it does not meet the new canonical standard for all possible checks.

The two largest gaps are:

1. It does not inspect `Registry.pol` or Local GPO provenance.
2. It omits several automatable states, especially the two machine Search policies, SettingSync, Teams removal, Edge browser removal, and two Internet Communication policies.

Therefore, preserve the current script as a useful static health check, but do not describe it as an exhaustive verifier of the complete canonical configuration.

## 7. Official documentation used to verify the control model

The control paths and semantics in this document were checked against current Microsoft documentation, including:

- Microsoft Security Compliance Toolkit and LGPO tool guidance.
- Windows Spotlight configuration and Experience Policy CSP mappings.
- Privacy Policy CSP mappings for Activity Feed and user activities.
- ADMX Group Policy CSP mappings for CDP and MMX.
- Notifications Policy CSP for WNS network-use policy.
- Search Policy CSP and Windows privacy connection-management guidance.
- SettingsSync ADMX Policy CSP and Windows Backup policy settings.
- ErrorReporting Policy CSP.
- Defender CSP.
- Microsoft Edge, WebView2, and Edge Update policy documentation.
- Office privacy-control documentation.
- Delivery Optimization Simple mode documentation.
