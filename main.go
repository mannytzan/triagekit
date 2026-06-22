package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type HostInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Timestamp    string `json:"timestamp"`
}

type ProcessInfo struct {
	Name          string `json:"name"`
	PID           string `json:"pid"`
	SessionName   string `json:"session_name"`
	SessionNumber string `json:"session_number"`
	MemoryUsage   string `json:"memory_usage"`
}

type TriageReport struct {
	HostInfo  HostInfo      `json:"host_info"`
	Processes []ProcessInfo `json:"processes"`
}

func collectHostInfo() HostInfo {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return HostInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Timestamp:    time.Now().Format(time.RFC3339),
	}
}

func collectProcesses() ([]ProcessInfo, error) {
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(string(output)))

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo

	for _, record := range records {
		if len(record) < 5 {
			continue
		}

		process := ProcessInfo{
			Name:          record[0],
			PID:           record[1],
			SessionName:   record[2],
			SessionNumber: record[3],
			MemoryUsage:   record[4],
		}

		processes = append(processes, process)
	}

	return processes, nil
}

func saveReport(report TriageReport) (string, error) {
	err := os.MkdirAll("reports", 0755)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("reports/triage-%s-%s.json", report.HostInfo.Hostname, timestamp)

	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filename, output, 0644)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func main() {
	hostInfo := collectHostInfo()

	processes, err := collectProcesses()
	if err != nil {
		fmt.Println("Error collecting processes:", err)
		return
	}

	report := TriageReport{
		HostInfo:  hostInfo,
		Processes: processes,
	}

	filename, err := saveReport(report)
	if err != nil {
		fmt.Println("Error saving report:", err)
		return
	}

	fmt.Println("Triage report saved to:", filename)
}
