package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const version = "0.2.0-dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "convert":
		return runConvert(args[1:], stdout, stderr)
	case "targets":
		for _, target := range supportedTargets {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", target.Name, target.SigmaTarget, target.Pipeline)
		}
		return 0
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	rulesDir := flags.String("rules", "rules", "directory containing Sigma YAML rules")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	result, err := validateRules(*rulesDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	for _, issue := range result.Issues {
		fmt.Fprintf(stderr, "%s: %s\n", issue.Path, issue.Message)
	}
	fmt.Fprintf(stdout, "validated %d rule(s): %d error(s)\n", result.RuleCount, len(result.Issues))
	if len(result.Issues) > 0 {
		return 1
	}
	return 0
}

func runConvert(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("convert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	rulesDir := flags.String("rules", "rules", "directory containing Sigma YAML rules")
	outputDir := flags.String("output", "generated", "directory for generated queries")
	targetNames := flags.String("targets", "splunk,elastic,crowdstrike", "comma-separated conversion targets")
	timeout := flags.Duration("timeout", 30*time.Second, "timeout for each conversion")
	sigmaBinary := flags.String("sigma-binary", "sigma", "sigma-cli executable")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	validation, err := validateRules(*rulesDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if len(validation.Issues) > 0 {
		for _, issue := range validation.Issues {
			fmt.Fprintf(stderr, "%s: %s\n", issue.Path, issue.Message)
		}
		fmt.Fprintln(stderr, "conversion stopped: validation failed")
		return 1
	}

	targets, err := selectTargets(*targetNames)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	converter := SigmaCLIConverter{Binary: *sigmaBinary, Timeout: *timeout}
	failures := 0
	for _, rule := range validation.Rules {
		for _, target := range targets {
			artifact, err := converter.Convert(context.Background(), rule.Path, target)
			if err != nil {
				fmt.Fprintf(stderr, "%s [%s]: %v\n", rule.Path, target.Name, err)
				failures++
				continue
			}
			path := artifactPath(*outputDir, target, rule)
			if err := writeArtifact(path, artifact); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", path, err)
				failures++
				continue
			}
			fmt.Fprintln(stdout, path)
		}
	}
	if failures > 0 {
		fmt.Fprintf(stderr, "conversion completed with %d failure(s)\n", failures)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "TriageKit - Go orchestration for Sigma detection-as-code")
	fmt.Fprintln(w, "\nUsage: triagekit <command> [options]")
	fmt.Fprintln(w, "\nCommands:\n  validate   validate Sigma rules and ATT&CK metadata\n  convert    convert rules for Splunk, Elastic, and CrowdStrike\n  targets    list supported conversion targets\n  version    print version")
}

type SigmaCLIConverter struct {
	Binary  string
	Timeout time.Duration
}

func (c SigmaCLIConverter) Convert(parent context.Context, rulePath string, target Target) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	args := []string{"convert", "-t", target.SigmaTarget}
	if target.Pipeline != "" {
		args = append(args, "-p", target.Pipeline)
	}
	args = append(args, rulePath)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("sigma-cli timed out after %s", c.Timeout)
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("sigma-cli: %s", message)
	}
	return stdout.Bytes(), nil
}

func writeArtifact(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640)
}
