# Everyday Sigma starter rules

These copy-ready examples cover process activity that SOC analysts commonly
investigate. They deliberately use one Windows process-creation log source and
common Sigma fields so the logic is easy to read and portable across TriageKit's
three conversion targets.

| Example | Why an analyst cares | Start the investigation with |
| --- | --- | --- |
| [Office application spawns a shell](office_spawns_shell.yml) | A document launching a command shell is a common initial-access or execution pattern. | Parent document, user, command line, file origin, and nearby child processes. |
| [Certutil downloads content](certutil_download.yml) | Attackers can abuse a signed Windows utility to retrieve payloads. | URL, destination path, file hash, network connection, and the parent process. |
| [PowerShell disables Defender](powershell_disables_defender.yml) | Security-control tampering often precedes payload execution. | Full command line, elevation, initiating user, other Defender changes, and later processes. |
| [Regsvr32 loads remote content](regsvr32_remote_content.yml) | `regsvr32` can proxy execution of a remote scriptlet. | Remote host, downloaded content, parent process, user, and subsequent network activity. |
| [Schtasks creates a task](schtasks_creates_task.yml) | Scheduled tasks are used by administrators and by attackers for persistence or execution. | Task name, command in `/tr`, creator, run account, host role, and whether the task later ran. |

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

For an explanation of every Sigma field and condition, see
[Write your first Sigma rule](../writing-your-first-rule.md).
