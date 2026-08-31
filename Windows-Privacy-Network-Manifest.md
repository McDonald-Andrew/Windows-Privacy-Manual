# Windows 10/11 Privacy Network Manifest

Snapshot: 2026-08-30

## Removed or blocked endpoints

| Endpoint / pattern                                         | Final state                    | Method / cause                                                                                   |
| ---------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------ |
| v10.events.data.microsoft.com                              | Removed                        | AllowTelemetry=0 + DiagTrack disabled                                                            |
| v20.events.data.microsoft.com                              | Removed                        | AllowTelemetry=0 + DiagTrack disabled                                                            |
| browser.events.data.msn.com                                | Removed                        | Microsoft.StartExperiencesApp removed                                                            |
| settings-win.data.microsoft.com                            | Hosts-sinkholed                | 0.0.0.0 and :: in hosts                                                                          |
| watson.events.data.microsoft.com                           | Removed                        | GPO: Disable Windows Error Reporting = Enabled                                                   |
| client.wns.windows.com                                     | Removed                        | WNS network-use policy + NoCloudApplicationNotification=1                                        |
| activity.windows.com                                       | Removed                        | EnableActivityFeed/PublishUserActivities/UploadUserActivities=0                                  |
| enterprise.activity.windows.com                            | Removed                        | Same Activity Feed policy                                                                        |
| cs.dds.microsoft.com                                       | Removed at source              | CDP/MMX off, CDP services disabled, work account removed, OS MSA blocked/local account, sync off |
| graph.microsoft.com (CrossDeviceResume source)             | Removed for background Resume  | Settings > Apps > Resume = Off                                                                   |
| inference.location.live.net                                | Removed                        | Settings > Privacy & security > Location > Location services = Off                               |
| agps.location.live.net                                     | Removed                        | Same Location switch                                                                             |
| fd.api.iris.microsoft.com                                  | Hosts-sinkholed                | Spotlight disabled + 0.0.0.0 and :: in hosts                                                     |
| assets.msn.com                                             | Removed with Widgets/Spotlight | Widgets and consumer-content policies                                                            |
| arc.msn.com                                                | Removed with Widgets/Spotlight | Widgets and consumer-content policies                                                            |
| api.msn.com                                                | Removed with Widgets/Spotlight | Widgets and consumer-content policies                                                            |
| www.msn.com                                                | Removed with Widgets/Spotlight | Widgets and consumer-content policies                                                            |
| c.msn.com                                                  | Removed with Widgets/Spotlight | Widgets and consumer-content policies                                                            |
| windows.msn.com                                            | Removed with Widgets/Spotlight | Widgets and consumer-content policies                                                            |
| e.clarity.ms / c.clarity.ms / www.clarity.ms               | Removed with source features   | Widgets/consumer-content surfaces disabled                                                       |
| sb.scorecardresearch.com                                   | Removed with source features   | Widgets/consumer-content surfaces disabled                                                       |
| www.bing.com (Windows Search integration)                  | Removed                        | GPO web-search disables + DisableSearchBoxSuggestions=1                                          |
| www.msftconnecttest.com                                    | Removed                        | NCSI active tests disabled                                                                       |
| dns.msftncsi.com                                           | Removed                        | NCSI active tests disabled                                                                       |
| array\*.prod.do.dsp.mp.microsoft.com                       | Removed                        | Delivery Optimization DODownloadMode=99                                                          |
| config.edge.skype.com                                      | Removed                        | Edge/WebView2/EdgeUpdate experimentation/config policies = 0                                     |
| ic3.events.data.microsoft.com                              | Removed with Teams             | Teams uninstalled                                                                                |
| teams.microsoft.com                                        | Removed with Teams             | Teams uninstalled                                                                                |
| teams.live.com                                             | Removed with Teams             | Teams uninstalled                                                                                |
| \*.trouter.skype.com                                       | Removed with Teams             | Teams uninstalled                                                                                |
| login.microsoftonline.com (idle Teams/work-account source) | Removed from idle background   | Teams removed + work/school account disconnected; not globally blocked                           |

## Disabled/removed Windows or app components

- DiagTrack: stopped + disabled.
- CDPSvc: stopped + disabled.
- CDPUserSvc: Start=4; UserServiceFlags=0.
- Microsoft.StartExperiencesApp: removed for installed users and provisioning.
- Microsoft Teams: uninstalled.
- Microsoft Edge browser: uninstalled; WebView2 kept.
- Widgets: disabled.
- Spotlight/consumer content: disabled.
- Activity Feed: disabled.
- WNS cloud notifications: disabled.
- Windows web search/Bing integration: disabled.
- Sync your settings/cloud settings sync: disabled.
- Connected-device CDP/MMX: disabled.
- Resume: Off.
- Workplace registration: disconnected and BlockAADWorkplaceJoin=1.
- Windows OS Microsoft account: switched to local account; "Users can't add or log on with Microsoft accounts".
- Windows Error Reporting upload: disabled.
- Windows Location services: Off.
- NCSI active probes: disabled.
- CEIP / Help "Did you know?" / Windows Messenger CEIP: disabled.
- Explorer SmartScreen: disabled by deliberate choice.
- Edge/WebView2/EdgeUpdate experimentation/config service: disabled.
- Delivery Optimization peer/coordination behavior: mode 99.
- Visual Studio SQM telemetry: disabled.
- VS Code telemetry and experiments: disabled.
- Office optional privacy/connected-experience settings: maximally restricted.

## Hosts file

0.0.0.0 settings-win.data.microsoft.com
:: settings-win.data.microsoft.com
0.0.0.0 fd.api.iris.microsoft.com
:: fd.api.iris.microsoft.com

The experimental cs.dds.microsoft.com Dynamic Keyword Address firewall block was removed. No permanent DDS firewall rule is intended.

## Intentionally kept endpoints / services

| Endpoint/component                                                   | Why kept                                                                 |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| reflector.defender.microsoft.com                                     | Defender connectivity/IPv6 probe                                         |
| tas02.cwsmu.update.microsoft.com / tas02.sls.update.microsoft.com    | Windows/Defender update metadata                                         |
| download.windowsupdate.com                                           | Windows/Defender updates                                                 |
| au.download.windowsupdate.com                                        | Windows/Defender updates and definition delta packages                   |
| ctldl.windowsupdate.com                                              | Root/disallowed certificate trust-list updates                           |
| time.windows.com                                                     | Windows Time synchronization                                             |
| login.live.com                                                       | wlidsvc/device authentication needed by Windows licensing/serviceability |
| licensing.mp.microsoft.com                                           | Windows/app licensing and activation                                     |
| storecatalogrevocation.storequality.microsoft.com                    | Revocation of malicious Store-app licenses                               |
| ecs.office.com                                                       | Office 2024 servicing/config; Office callers identified                  |
| mobile.events.data.microsoft.com when OfficeClickToRun.exe is caller | Office Click-to-Run servicing                                            |
| officeclient.microsoft.com                                           | Office shared/serviceability infrastructure                              |
| odc.officeapps.live.com                                              | Office shared/serviceability infrastructure                              |
| mrodevicemgr.officeapps.live.com                                     | Office serviceability infrastructure                                     |
| f.c2r.ts.cdn.office.net                                              | Office Click-to-Run update CDN                                           |
| substrate.office.com                                                 | Office account/connected infrastructure when Office uses it              |
| edge.microsoft.com                                                   | WebView2 Runtime component/support traffic                               |
| catalog.gamepass.com                                                 | Gaming Services; deliberately left alone                                 |
| device.auth.xboxlive.com                                             | Xbox authentication/XblAuthManager                                       |
| AMER33.azure-devices.net:8883                                        | Dell SupportAssistAgent using Azure IoT                                  |
| dellupdater.dell.com                                                 | Dell SupportAssist/remediation/update                                    |
| hb.apis.dell.com                                                     | Dell support software                                                    |
| tm-sdk.platinumai.net                                                | Dell SupportAssist-related infrastructure                                |

## Defender state to preserve

- AntivirusEnabled=True
- RealTimeProtectionEnabled=True
- BehaviorMonitorEnabled=True
- IoavProtectionEnabled=True

## Update/trust state to preserve

- Configure Automatic Updates = Not Configured.
- Automatic Root Certificates Update remains allowed.
- DisableRootAutoUpdate = 0 or absent.
- Delivery Optimization stays at mode 99.

## Future re-verification

1. Run the companion Windows-Privacy-Audit.ps1 as Administrator.
2. Check any item marked CHECK.
3. For network verification: enable 5156 + 4688, cold boot offline, start Wireshark, reconnect, idle 25-30 minutes.
4. Removed endpoints above should have no external TCP/TLS flow.
5. Hosts-sinkholed endpoints may appear in DNS Client logs resolving to 0.0.0.0/::; that is success.
6. A kept endpoint is only expected when its caller matches the identified security/servicing component.
7. Disable temporary audit logging afterward.
