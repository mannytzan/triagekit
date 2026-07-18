# Security Policy

## Supported versions

TriageKit is currently under active development. Security fixes are applied to
the latest revision of the `main` branch. Older revisions and development
forks are not maintained separately.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
**Security** tab by selecting **Report a vulnerability**. Include:

- The affected component and revision.
- Reproduction steps or a minimal proof of concept.
- The potential security impact.
- Any suggested mitigation, if known.

Do not open a public issue, discussion, or pull request containing exploit
details before the report has been reviewed. If private vulnerability reporting
is unavailable, contact the repository owner through their GitHub profile
without including sensitive technical details in a public message.

You should receive an acknowledgement within seven days. After triage, the
maintainer will coordinate remediation and responsible disclosure with the
reporter. Timelines depend on severity, exploitability, and release complexity.

## Scope

Reports about TriageKit's Go application, conversion orchestration, dependency
chain, GitHub Actions workflows, and unsafe handling of Sigma content are in
scope. Vulnerabilities in Splunk, Elastic, CrowdStrike, Sigma CLI, or other
third-party services should also be reported to the affected upstream project.

Never include live credentials, customer telemetry, proprietary detection
content, or personal data in a vulnerability report or reproduction fixture.
