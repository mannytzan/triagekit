# MITRE ATT&CK detection coverage

This is a practical coverage map, not a claim that Sigma can detect every ATT&CK
technique. ATT&CK describes adversary behavior; Sigma describes searches over
available telemetry. A useful rule requires an observable event, reliable field
mapping, and enough context to separate malicious behavior from normal work.

The review uses the current [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/enterprise/)
and the [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).

## Implemented starter coverage

| ATT&CK behavior | Starter rule | Primary telemetry | Expected signal |
| --- | --- | --- | --- |
| T1204.002 User Execution: Malicious File | [Office spawns shell](examples/office_spawns_shell.yml) | Windows process creation with parent | Medium-high |
| T1059.001 PowerShell | [Encoded PowerShell](../rules/windows/process_creation/suspicious_encoded_powershell.yml) | Windows process creation and command line | Medium |
| T1105 Ingress Tool Transfer | [Certutil download](examples/certutil_download.yml) | Windows process creation and command line | Medium |
| T1218.005 Mshta | [Mshta remote content](examples/mshta_remote_content.yml) | Windows process creation and command line | High |
| T1218.010 Regsvr32 | [Regsvr32 remote scriptlet](examples/regsvr32_remote_content.yml) | Windows process creation and command line | High |
| T1053.005 Scheduled Task | [Schtasks creates task](examples/schtasks_creates_task.yml) | Windows process creation and command line | Medium |
| T1053.003 Cron | [Linux](examples/linux_crontab_modified.yml) / [macOS](examples/macos_crontab_modified.yml) crontab modification | Unix process creation and command line | Low-medium |
| T1547.001 Registry Run Keys / Startup Folder | [Run and RunOnce modified](examples/registry_run_keys.yml) | Windows registry value-set events | Medium |
| T1543.003 Windows Service | [Sc.exe creates service](examples/windows_service_created.yml) | Windows process creation and command line | Medium |
| T1562.001 Impair Defenses | [PowerShell disables Defender](examples/powershell_disables_defender.yml) | Windows process creation and command line | High |
| T1003.001 LSASS Memory | [LSASS dump](examples/lsass_memory_dump.yml) | Windows process creation and command line | High |
| T1003.002/T1003.004 Registry credential stores | [Credential hive dump](examples/registry_credential_hive_dump.yml) | Windows process creation and command line | High |
| T1685.005 Clear Windows Event Logs | [Wevtutil clears logs](examples/windows_event_logs_cleared.yml) | Windows process creation and command line | High |
| T1490 Inhibit System Recovery | [Vssadmin deletes shadows](examples/shadow_copies_deleted.yml) | Windows process creation and command line | High |
| T1571 Non-Standard Port | [Destination port 4444](examples/network_connection_port_4444.yml) | Windows network connection events | Low without enrichment |

## Good next candidates

These behaviors can make useful detections, but should be implemented only when
the required telemetry and environment-specific allowlists are known:

| Candidate | ATT&CK | Why it is not a default starter alert |
| --- | --- | --- |
| New local or domain account | T1136 | Requires account-management audit events and approved provisioning context. |
| User added to privileged group | T1098 | Requires group-change audit events and identity context. |
| DCSync behavior | T1003.006 | Requires directory replication access telemetry and a domain-controller allowlist. |
| Remote service execution | T1569.002 | Service activity is common in management tools; correlate source host and account. |
| WMI remote execution | T1047 | WMI is heavily used by legitimate administration and inventory tools. |
| RDP from unusual source | T1021.001 | Requires authentication/network telemetry and an environment-specific source baseline. |
| Linux or macOS system service persistence | T1543.001, T1543.002, T1543.004 | Needs file or service-manager telemetry and platform-specific pipelines. |
| Rare outbound destination or newly seen domain | T1071/T1105 | Requires DNS/proxy history and enrichment, not a static Sigma value list. |
| Mass file modification associated with ransomware | T1486 | Requires file telemetry plus rate or correlation logic beyond a simple event rule. |
| Suspicious cloud control-plane changes | Varies | Requires provider-specific audit schemas, identities, and organization policy. |

## Prioritize detections responsibly

1. Start with credential dumping, defense impairment, persistence, and recovery
   inhibition because they are consequential and often uncommon.
2. Validate that command lines, parent processes, registry writes, and network
   connections are actually collected before enabling a rule.
3. Combine weak signals. A discovery command or destination port alone rarely
   proves compromise.
4. Test with approved simulations and measure match volume before alerting.
5. Revisit ATT&CK mappings periodically; technique identifiers and tactics can
   change as the framework evolves.
