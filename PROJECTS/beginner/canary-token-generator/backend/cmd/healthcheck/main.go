// ©AngelaMos | 2026
// main.go

package main

import (
	"net/http"
	"os"
	"time"
)

const (
	healthURL  = "http://127.0.0.1:8080/healthz"
	httpDialTO = 2 * time.Second
)

func main() {
	client := &http.Client{Timeout: httpDialTO}
	resp, err := client.Get(healthURL)
	if err != nil {
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(1)
	}
}
