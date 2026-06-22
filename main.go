package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
)

type HostInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Timestamp    string `json:"timestamp"`
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

func main() {
	hostInfo := collectHostInfo()

	output, err := json.MarshalIndent(hostInfo, "", "  ")
	if err != nil {
		fmt.Println("Error creating JSON:", err)
		return
	}

	fmt.Println(string(output))
}
