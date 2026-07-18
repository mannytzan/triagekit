# TriageKit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)


TriageKit is a Go-first detection-as-code lab for building, validating, and
converting portable Sigma detections for Splunk, Elastic, and CrowdStrike
Falcon Next-Gen SIEM/LogScale.

```text
Sigma rule -> CI validation -> platform query -> SIEM deployment
           -> alert measurement -> tuning -> improved rule
```

The Sigma rule is the source of truth. Generated queries, deployment records,
and alert measurements provide evidence for improving that rule.

## Why this matters

Detection content often becomes a collection of queries maintained separately
inside individual SIEMs. That makes changes difficult to review, test,
reproduce, or compare across platforms. TriageKit brings normal software
engineering controls to detection development:

- Store vendor-neutral detection logic in Git.
- Catch incomplete metadata and malformed rules before deployment.
- Produce consistent Splunk SPL, Elastic Lucene, and CrowdStrike CQL artifacts.
- Review rule logic and generated queries together in pull requests.
- Document MITRE ATT&CK coverage and expected false positives.
- Build toward measurable tuning instead of changing production queries by intuition.
- Reproduce conversion results through a pinned CI toolchain.

This gives detection engineers a visible history of what changed, why it
changed, where it was deployed, and whether the change improved alert quality.

## Current capabilities

```text
rules/**/*.yml
      |
      v
Go policy validation
      |
      v
Official pySigma backends
      |----------------------|-----------------------|
      v                      v                       v
  Splunk SPL            Elastic Lucene        CrowdStrike CQL
```

TriageKit currently implements rule authoring, policy validation, CI, and
platform conversion. SIEM deployment, alert measurement, and tuning comparison
are the next stages.

Validation requires every rule to contain:

- A UUID, title, description, and author
- A log source and detection condition
- A supported severity level
- Expected false-positive activity
- At least one MITRE ATT&CK technique tag, such as `attack.t1059.001`

## Requirements

- Go 1.21 or newer
- Python 3.10 or newer
- Sigma CLI and the Splunk, Elasticsearch, and CrowdStrike pySigma backends

Install the conversion toolchain:

```powershell
python -m pip install `
  sigma-cli==3.1.0 `
  pysigma-backend-splunk==2.1.0 `
  pysigma-backend-elasticsearch==2.1.0 `
  pysigma-backend-crowdstrike==3.0.0
```

Using a Python virtual environment is recommended.

## Choose how to use TriageKit

There are two supported workflows:

| Workflow | Best for | What happens |
| --- | --- | --- |
| Local | Writing and testing rules on a workstation | Go validates rules and Sigma CLI writes queries to `generated/` |
| GitHub | Team review and repeatable CI | A pull request triggers validation, conversion, and an artifact containing all generated queries |

Neither workflow currently connects to a live SIEM. TriageKit produces queries
that can be reviewed and then copied or imported into the target platform. Live
query execution, deployment, and alert measurement are planned stages described
in the roadmap.

## Use locally

### 1. Clone the repository

```powershell
git clone https://github.com/mannytzan/triagekit.git
cd triagekit
```

### 2. Create an isolated Python environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the pinned conversion packages shown in the Requirements section.

### 3. Write a Sigma rule

Add a `.yml` file beneath `rules/`. The included
`suspicious_encoded_powershell.yml` rule demonstrates the expected structure,
ATT&CK mapping, and false-positive documentation.

### 4. Validate the rules

```powershell
go run . validate
```

Validate a different directory with `-rules`:

```powershell
go run . validate -rules path/to/rules
```

Validation exits nonzero when a rule violates repository policy, making the
same command suitable for local development and CI.

### 5. Generate platform queries

```powershell
go run . convert
```

By default, TriageKit converts every valid rule for all three platforms:

```text
generated/
|-- splunk/*.spl
|-- elastic/*.lucene
`-- crowdstrike/*.cql
```

Convert selected platforms or choose another output directory:

```powershell
go run . convert -targets splunk,crowdstrike
go run . convert -output build/queries
```

Each conversion has a timeout. A backend failure is reported with the rule and
target that caused it:

```powershell
go run . convert -timeout 60s
```

### 6. Use the generated query

Open the relevant file under `generated/`, review the field mappings, and paste
the query into the corresponding search interface:

- `.spl` in Splunk Search
- `.lucene` in Kibana or Elastic Security
- `.cql` in CrowdStrike Falcon Next-Gen SIEM or LogScale

Always test the generated query against representative telemetry before turning
it into a production alert. Sigma processing pipelines translate common field
names, but each organization's ingestion and normalization can differ.

### 7. Inspect supported targets

```powershell
go run . targets
go run . help
```

## Use through GitHub

Users who do not want to configure Go and Python locally can use the repository's
GitHub Actions workflow:

1. Fork [mannytzan/triagekit](https://github.com/mannytzan/triagekit).
2. Enable Actions in the fork if GitHub prompts for approval.
3. Create a branch and add or edit a rule beneath `rules/`.
4. Open a pull request against the fork's `main` branch.
5. Open the `detections` workflow run linked from the pull request.
6. Confirm that validation, tests, and all three conversions passed.
7. Download the `sigma-queries` artifact from the workflow run.
8. Review the appropriate `.spl`, `.lucene`, or `.cql` file before using it in a SIEM.

An experienced contributor can use Git locally to submit the change:

```bash
git checkout -b detection/my-new-rule
# Add or edit a rule under rules/
git add rules/
git commit -m "Add my new Sigma detection"
git push origin detection/my-new-rule
```

The same workflow can also be started by editing a rule directly in GitHub's
web interface and opening a pull request.

### What GitHub Actions does

The GitHub Actions workflow runs on pull requests and pushes to `main`. It:

1. Installs the pinned Go and Python toolchains.
2. Runs Go tests and static analysis.
3. Validates every Sigma rule.
4. Converts rules for Splunk, Elastic, and CrowdStrike.
5. Uploads the generated queries as a workflow artifact.

No live SIEM credentials are required or used. The workflow validates and
converts detection content but does not query or modify Splunk, Elastic, or
CrowdStrike. Future deployment jobs should use protected GitHub environments,
manual approval, and platform-specific secrets.

## What happens to a rule

For example, when a contributor adds a process-creation Sigma rule:

```text
rules/windows/process_creation/example.yml
                 |
                 v
      Go checks metadata and ATT&CK tags
                 |
                 v
       Sigma CLI converts the rule
         |             |             |
         v             v             v
    Splunk SPL    Elastic Lucene  CrowdStrike CQL
         |             |             |
         `-------------+-------------'
                       |
                       v
          Review and test in the chosen SIEM
```

Editing the Sigma source and running the workflow again regenerates every
platform query. This prevents three manually maintained detection versions from
drifting apart.

## CrowdStrike compatibility

CrowdStrike conversion uses the `log_scale` target with the
`crowdstrike_falcon` processing pipeline. Falcon telemetry does not provide an
equivalent for every generic Sigma field. When a category or field cannot be
mapped safely, that target fails explicitly rather than emitting a misleading
query. Successful output uses CrowdStrike Query Language (CQL).

## Repository layout

```text
.github/workflows/      CI validation and conversion
rules/                  source-controlled Sigma rules
generated/              generated queries (ignored by Git)
main.go                 CLI and sigma-cli orchestration
rules.go                rule and ATT&CK policy validation
targets.go              platform conversion definitions
rules_test.go           repository and unit tests
```

## Development

```powershell
go fmt ./...
go test ./...
go vet ./...
go run . validate
```

## Roadmap

1. Deploy generated queries through Splunk, Elastic, and CrowdStrike adapters.
2. Record alert volume, analyst verdicts, and false-positive rates by rule version.
3. Compare baseline and tuned rule metrics in CI.
4. Feed approved tuning changes back into the source Sigma rule.
5. Add conversion drift checks and ATT&CK coverage views.

The goal is a closed detection-engineering feedback loop: detections should not
only deploy consistently; their operational quality should be measurable and
improve over time.

## Security and responsible use

Do not commit live SIEM credentials, customer telemetry, exported alerts, or
proprietary detection content. Keep platform credentials in protected GitHub
environments or an approved secrets manager if deployment capabilities are
added in the future.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

TriageKit is available under the [MIT License](LICENSE).
