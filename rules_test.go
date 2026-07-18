package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRepositoryRules(t *testing.T) {
	result, err := validateRules("rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
	if result.RuleCount == 0 {
		t.Fatal("expected at least one rule")
	}
}

func TestValidateRuleRequiresAttackTechnique(t *testing.T) {
	rule := SigmaRule{
		Title: "test", ID: "77b23624-9db8-4d75-8c72-ef749f3e1b20",
		Description: "test", Author: "test", Level: "medium", Path: "test.yml",
		Logsource:      map[string]any{"product": "windows"},
		Detection:      map[string]any{"condition": "selection"},
		FalsePositives: []string{"test activity"}, Tags: []string{"attack.execution"},
	}
	issues := validateRule(rule)
	if len(issues) != 1 || issues[0].Message != "at least one MITRE ATT&CK technique tag is required" {
		t.Fatalf("unexpected issues: %#v", issues)
	}
}

func TestSelectTargets(t *testing.T) {
	targets, err := selectTargets("crowdstrike,splunk,crowdstrike")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].SigmaTarget != "log_scale" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestWriteArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elastic", "rule.lucene")
	if err := writeArtifact(path, []byte("query")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "query" {
		t.Fatalf("unexpected artifact: %q", data)
	}
}
