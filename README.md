# TriageKit

TriageKit is a Go-based endpoint triage collector built for blue-team incident response practice.

## Current Features

- Collects hostname
- Collects operating system
- Collects system architecture
- Adds collection timestamp
- Outputs structured JSON

## Example Output

```json
{
  "hostname": "DESKTOP-12345",
  "os": "windows",
  "architecture": "amd64",
  "timestamp": "2026-06-21T14:30:00-04:00"
}