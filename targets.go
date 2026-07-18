package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Target struct {
	Name, SigmaTarget, Pipeline, Extension string
}

var supportedTargets = []Target{
	{Name: "splunk", SigmaTarget: "splunk", Pipeline: "splunk_windows", Extension: ".spl"},
	{Name: "elastic", SigmaTarget: "lucene", Pipeline: "ecs_windows", Extension: ".lucene"},
	{Name: "crowdstrike", SigmaTarget: "log_scale", Pipeline: "crowdstrike_falcon", Extension: ".cql"},
}

func selectTargets(value string) ([]Target, error) {
	byName := make(map[string]Target, len(supportedTargets))
	for _, target := range supportedTargets {
		byName[target.Name] = target
	}
	seen := map[string]bool{}
	var selected []Target
	for _, name := range strings.Split(value, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		target, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unsupported target %q (choose splunk, elastic, or crowdstrike)", name)
		}
		if !seen[name] {
			selected = append(selected, target)
			seen[name] = true
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	return selected, nil
}

func artifactPath(root string, target Target, rule SigmaRule) string {
	name := strings.TrimSuffix(filepath.Base(rule.Path), filepath.Ext(rule.Path))
	return filepath.Join(root, target.Name, name+target.Extension)
}
