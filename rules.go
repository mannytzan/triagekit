package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type SigmaRule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Author         string         `yaml:"author"`
	Logsource      map[string]any `yaml:"logsource"`
	Detection      map[string]any `yaml:"detection"`
	FalsePositives []string       `yaml:"falsepositives"`
	Level          string         `yaml:"level"`
	Tags           []string       `yaml:"tags"`
	Path           string         `yaml:"-"`
}

type ValidationIssue struct{ Path, Message string }
type ValidationResult struct {
	RuleCount int
	Rules     []SigmaRule
	Issues    []ValidationIssue
}

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	attackPattern = regexp.MustCompile(`^attack\.t[0-9]{4}(\.[0-9]{3})?$`)
	validLevels   = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}
)

func validateRules(root string) (ValidationResult, error) {
	result := ValidationResult{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || (filepath.Ext(path) != ".yml" && filepath.Ext(path) != ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var rule SigmaRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			result.Issues = append(result.Issues, ValidationIssue{path, "invalid YAML: " + err.Error()})
			return nil
		}
		rule.Path = path
		result.RuleCount++
		result.Rules = append(result.Rules, rule)
		result.Issues = append(result.Issues, validateRule(rule)...)
		return nil
	})
	if err != nil {
		return result, fmt.Errorf("walk rules: %w", err)
	}
	if result.RuleCount == 0 {
		return result, fmt.Errorf("no Sigma YAML rules found under %s", root)
	}
	sort.Slice(result.Issues, func(i, j int) bool { return result.Issues[i].Path < result.Issues[j].Path })
	return result, nil
}

func validateRule(rule SigmaRule) []ValidationIssue {
	var messages []string
	if strings.TrimSpace(rule.Title) == "" {
		messages = append(messages, "title is required")
	}
	if !uuidPattern.MatchString(rule.ID) {
		messages = append(messages, "id must be a UUID")
	}
	if strings.TrimSpace(rule.Description) == "" {
		messages = append(messages, "description is required")
	}
	if strings.TrimSpace(rule.Author) == "" {
		messages = append(messages, "author is required")
	}
	if len(rule.Logsource) == 0 {
		messages = append(messages, "logsource is required")
	}
	if len(rule.Detection) == 0 {
		messages = append(messages, "detection is required")
	}
	if _, ok := rule.Detection["condition"]; !ok {
		messages = append(messages, "detection.condition is required")
	}
	if !validLevels[strings.ToLower(rule.Level)] {
		messages = append(messages, "level must be informational, low, medium, high, or critical")
	}
	if len(rule.FalsePositives) == 0 {
		messages = append(messages, "falsepositives must document expected benign activity")
	}
	hasTechnique := false
	for _, tag := range rule.Tags {
		if attackPattern.MatchString(strings.ToLower(tag)) {
			hasTechnique = true
			break
		}
	}
	if !hasTechnique {
		messages = append(messages, "at least one MITRE ATT&CK technique tag is required")
	}
	issues := make([]ValidationIssue, 0, len(messages))
	for _, message := range messages {
		issues = append(issues, ValidationIssue{rule.Path, message})
	}
	return issues
}
