# Write your first Sigma rule

You do not need prior Sigma experience for this walkthrough. A Sigma rule is a
YAML document that describes suspicious activity using common field names. A
converter turns that description into a query for your SIEM.

Start by reading the working rule at
[`rules/windows/process_creation/suspicious_encoded_powershell.yml`](../rules/windows/process_creation/suspicious_encoded_powershell.yml).
It looks for PowerShell or `pwsh` combined with an encoded-command flag.

## Understand the working example

| Field | What it answers |
| --- | --- |
| `title`, `description` | What behavior does this detect, and why does it matter? |
| `id` | What permanently identifies this rule? Every new rule needs a new UUID. |
| `status` | How mature is the rule? Start new rules at `test`. |
| `logsource` | Which event family is required? This example needs Windows process-creation events. |
| `detection` | Which field values should match, and how are the selections combined? |
| `falsepositives` | Which legitimate activity might trigger the rule? |
| `level` | How urgently should an analyst investigate? |
| `tags` | Which MITRE ATT&CK behavior does the rule cover? |

The example has two selections:

- `selection_image` matches a process whose `Image` ends in `powershell.exe` or
  `pwsh.exe`.
- `selection_flag` matches a `CommandLine` containing an encoded-command flag.
- `condition: all of selection_*` requires both selections to match the same
  event. Changing `all` to `1` would make the rule much noisier.

Modifiers such as `|endswith` and `|contains` tell Sigma how to compare a field.
They are preferable to hand-written wildcards because each backend can translate
them appropriately.

## Make a rule of your own

Copy the working example to a descriptive filename under the same directory:

```powershell
Copy-Item rules/windows/process_creation/suspicious_encoded_powershell.yml `
  rules/windows/process_creation/my_first_rule.yml
```

On Linux or macOS:

```bash
cp rules/windows/process_creation/suspicious_encoded_powershell.yml \
  rules/windows/process_creation/my_first_rule.yml
```

Before validating, change at least these fields:

1. Give the rule a precise `title` and `description`.
2. Generate a new `id` with `New-Guid` in PowerShell or `uuidgen` on Linux/macOS.
3. Adjust the values under `detection` to describe the behavior you want.
4. Write down realistic benign causes under `falsepositives`.
5. Select the closest ATT&CK technique from the
   [MITRE ATT&CK technique list](https://attack.mitre.org/techniques/) and use a
   tag such as `attack.t1059.001`.

Keep the first rule narrow: one event category, one suspicious behavior, and a
condition you can explain in a sentence. Do not put real credentials, customer
data, or sensitive event samples in a rule.

## Check your work

From the repository root, run:

```powershell
go run . validate
```

A successful result looks like:

```text
validated 2 rule(s): 0 error(s)
```

The count will vary with the number of rules. TriageKit prints the filename and
a specific message when required metadata is missing. Fix every error before
conversion.

Then generate just one query format while iterating:

```powershell
go run . convert -targets splunk
```

When the rule is ready, generate all supported formats:

```powershell
go run . convert
```

The generated query is a starting point, not proof that a detection is safe for
production. Review its field mappings and run it over representative telemetry.
Record what benign activity matched, then update `falsepositives` or narrow the
rule logic before creating an alert.

## Common first-rule problems

| Message or symptom | What to check |
| --- | --- |
| `id must be a UUID` | Replace the copied ID with the complete output of `New-Guid` or `uuidgen`. |
| `detection.condition is required` | Add a `condition` that references your selection names. |
| ATT&CK technique required | Add a technique tag, not only a tactic tag such as `attack.execution`. |
| YAML parse error | Use spaces, not tabs, and align list items at the same indentation. |
| One target fails conversion | The backend may not map that log source or field; read the named target's error and try a supported common field. |
| Query runs but finds nothing | Confirm your SIEM has the required event source and maps Sigma fields to your schema. |
