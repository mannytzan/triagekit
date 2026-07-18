# Everyday Sigma starter rules

These copy-ready examples cover endpoint activity that SOC analysts commonly
investigate. The Windows rules use common Sigma fields and are tested against
TriageKit's three conversion targets. The Linux and macOS rules are included as
authoring examples; see the Unix compatibility note before converting them.

| Example | Why an analyst cares | Start the investigation with |
| --- | --- | --- |
| [Office application spawns a shell](office_spawns_shell.yml) | A document launching a command shell is a common initial-access or execution pattern. | Parent document, user, command line, file origin, and nearby child processes. |
| [Certutil downloads content](certutil_download.yml) | Attackers can abuse a signed Windows utility to retrieve payloads. | URL, destination path, file hash, network connection, and the parent process. |
| [PowerShell disables Defender](powershell_disables_defender.yml) | Security-control tampering often precedes payload execution. | Full command line, elevation, initiating user, other Defender changes, and later processes. |
| [Regsvr32 loads remote content](regsvr32_remote_content.yml) | `regsvr32` can proxy execution of a remote scriptlet. | Remote host, downloaded content, parent process, user, and subsequent network activity. |
| [Schtasks creates a task](schtasks_creates_task.yml) | Scheduled tasks are used by administrators and by attackers for persistence or execution. | Task name, command in `/tr`, creator, run account, host role, and whether the task later ran. |
| [Run or RunOnce key modified](registry_run_keys.yml) | These registry locations start programs when a user signs in and are common persistence locations. | Hive and value path, value data, writing process, user, signature, and creation time. |
| [Connection to destination port 4444](network_connection_port_4444.yml) | Port 4444 is often used in labs and by some reverse shells, though the port alone is not an IoC. | Destination IP/domain, process, user, host role, connection frequency, and threat-intelligence context. |
| [Linux crontab modified](linux_crontab_modified.yml) | Cron can provide recurring execution and persistence. | User, installed schedule, referenced script, file ownership, parent process, and related logins. |
| [macOS crontab modified](macos_crontab_modified.yml) | Cron remains available on macOS even though launchd is more common. | User, installed schedule, referenced script, file provenance, parent process, and related logins. |

## Run an example

From the repository root, validate all starter rules without changing the main
`rules/` directory:

```powershell
go run . validate -rules docs/examples
```

Convert them into a separate output directory:

```powershell
go run . convert -rules docs/examples -output generated/examples
```

### Unix compatibility

The pinned backends expose Windows pipelines for all three TriageKit targets,
but do not provide an equivalent Linux pipeline across Splunk, Elastic, and
CrowdStrike. The macOS Elastic backend has a dedicated pipeline, but the current
CLI does not yet select pipelines per operating system. For that reason:

- `go run . validate -rules docs/examples` checks every example, including Unix.
- Treat the Linux and macOS cron rules as readable Sigma source examples.
- Do not use TriageKit's current `convert` output for those two rules; it would
  apply Windows-oriented mappings. Convert them only after configuring a
  processing pipeline that matches your telemetry schema.

To adopt one, copy it into the source rule tree, generate a new UUID, and update
the author and false-positive notes for your environment:

```powershell
Copy-Item docs/examples/certutil_download.yml `
  rules/windows/process_creation/certutil_download.yml
(New-Guid).Guid
```

On Linux or macOS, use `cp` and `uuidgen` instead. Run `go run . validate`
afterward.

## Tune before alerting

These examples are starting points, not production-ready promises. Before
enabling an alert:

1. Confirm the required process telemetry and fields exist in your SIEM.
2. Run the generated query over at least several days of representative data.
3. Review matches with endpoint, identity, network, and file context.
4. Add exclusions only for a specific, understood benign pattern. Avoid broad
   exclusions for an entire executable or administrator group.
5. Record expected benign activity in `falsepositives` and choose a severity
   that matches your response process.
6. Test a known-safe simulation in an approved lab and confirm the alert carries
   enough context for triage.

Port `4444` is a behavioral lead, not a known-bad indicator by itself. Enrich
the destination address with current threat intelligence and process context;
do not label a connection malicious solely because of its port number.

For an explanation of every Sigma field and condition, see
[Write your first Sigma rule](../writing-your-first-rule.md).
