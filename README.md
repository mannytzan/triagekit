# TriageKit

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

## Usage

### 1. Write a Sigma rule

Add a `.yml` file beneath `rules/`. The included
`suspicious_encoded_powershell.yml` rule demonstrates the expected structure,
ATT&CK mapping, and false-positive documentation.

### 2. Validate the rules

```powershell
go run . validate
```

Validate a different directory with `-rules`:

```powershell
go run . validate -rules path/to/rules
```

Validation exits nonzero when a rule violates repository policy, making the
same command suitable for local development and CI.

### 3. Generate platform queries

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

### 4. Inspect supported targets

```powershell
go run . targets
go run . help
```

## CI workflow

The GitHub Actions workflow runs on pull requests and pushes to `main`. It:

1. Installs the pinned Go and Python toolchains.
2. Runs Go tests and static analysis.
3. Validates every Sigma rule.
4. Converts rules for Splunk, Elastic, and CrowdStrike.
5. Uploads the generated queries as a workflow artifact.

No live SIEM credentials are required for validation or conversion. Future
deployment jobs should use protected environments and platform-specific GitHub
secrets.

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
