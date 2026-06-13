package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Common ports to scan
var commonPorts = []int{
	21,   // FTP
	22,   // SSH
	23,   // Telnet
	25,   // SMTP
	53,   // DNS
	80,   // HTTP
	110,  // POP3
	135,  // MSRPC
	139,  // NetBIOS
	143,  // IMAP
	443,  // HTTPS
	445,  // SMB
	1433, // MS SQL
	3306, // MySQL
	3389, // RDP
	5432, // PostgreSQL
	8080, // HTTP Alt
}

// Structs for scan results
type PortResult struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
}

type ScanReport struct {
	Target   string       `json:"target"`
	ScanTime string       `json:"scan_time"`
	Ports    []PortResult `json:"ports"`
}

func main() {
	if len(os.Args) < 2 {
		printUsageAndExit()
	}

	command := os.Args[1]

	switch command {
	case "scan":
		runScan(os.Args[2:])
	case "inspect":
		runInspect(os.Args[2:])
	case "explain":
		runExplain(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsageAndExit()
	}
}

func printUsageAndExit() {
	fmt.Println("Usage: netsage <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  scan <target>                  Scan standard ports on a target host")
	fmt.Println("  inspect --port <n> <target>    Perform service check and banner grab on a port")
	fmt.Println("  explain <results.json>         Generate a natural-language security report via AI")
	os.Exit(1)
}

func runScan(args []string) {
	if len(args) < 1 {
		fmt.Println("Error: Target host is required. Example: netsage scan 192.168.1.1")
		os.Exit(1)
	}
	target := args[0]

	fmt.Printf("[*] Starting TCP port scan on target: %s\n", target)
	
	// Resolve host first
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		fmt.Printf("[-] Error: Failed to resolve host %s\n", target)
		os.Exit(1)
	}
	ip := ips[0].String()
	fmt.Printf("[*] Resolved target IP: %s\n", ip)

	var wg sync.WaitGroup
	resultsChan := make(chan PortResult, len(commonPorts))
	semaphore := make(chan struct{}, 10) // Limit concurrency to 10 workers

	startTime := time.Now()

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire token
			defer func() { <-semaphore }() // Release token

			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err != nil {
				return // Closed
			}
			defer conn.Close()

			// Port is open! Try to grab a banner
			banner := ""
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			
			// For HTTP, write a probe to get a response header
			if p == 80 || p == 8080 {
				conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
			}

			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err == nil && n > 0 {
				banner = strings.TrimSpace(string(buf[:n]))
				// Normalize HTTP response banner to first line
				if strings.Contains(banner, "HTTP/") {
					lines := strings.Split(banner, "\r\n")
					if len(lines) > 0 {
						banner = lines[0]
					}
				}
			}

			// Map simple service names
			service := getServiceName(p)

			resultsChan <- PortResult{
				Port:    p,
				State:   "open",
				Service: service,
				Banner:  banner,
			}
		}(port)
	}

	// Wait for scan to complete in background
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var openPorts []PortResult
	fmt.Printf("\n%-6s %-10s %-15s %-30s\n", "PORT", "STATE", "SERVICE", "BANNER")
	fmt.Println(strings.Repeat("-", 65))
	
	for res := range resultsChan {
		openPorts = append(openPorts, res)
		fmt.Printf("%-6d %-10s %-15s %-30s\n", res.Port, res.State, res.Service, res.Banner)
	}

	duration := time.Since(startTime)
	fmt.Printf("\n[*] Scan finished in %s. Found %d open port(s).\n", duration.Round(time.Millisecond), len(openPorts))

	// Save to results.json
	report := ScanReport{
		Target:   target,
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		Ports:    openPorts,
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("[-] Failed to serialize JSON report: %v\n", err)
		return
	}

	outputFile := "results.json"
	err = os.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		fmt.Printf("[-] Failed to write results.json: %v\n", err)
	} else {
		absPath, _ := filepath.Abs(outputFile)
		fmt.Printf("[+] Results saved to: %s\n", absPath)
	}
}

func runInspect(args []string) {
	inspectFlags := flag.NewFlagSet("inspect", flag.ExitOnError)
	portFlag := inspectFlags.Int("port", 0, "Port number to inspect")
	
	if len(args) < 2 {
		fmt.Println("Error: Inspect requires --port <n> <target>. Example: netsage inspect --port 80 192.168.1.5")
		os.Exit(1)
	}

	inspectFlags.Parse(args)
	remaining := inspectFlags.Args()

	if *portFlag <= 0 || len(remaining) < 1 {
		fmt.Println("Error: Invalid arguments. Usage: netsage inspect --port <n> <target>")
		os.Exit(1)
	}

	port := *portFlag
	target := remaining[0]

	fmt.Printf("[*] Inspecting port %d on target %s...\n", port, target)

	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		fmt.Printf("[-] Error connecting to %s: %v\n", address, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("[+] Connection established to %s!\n", address)

	// Send probe for HTTP
	if port == 80 || port == 8080 || port == 443 {
		fmt.Println("[*] Sending HTTP probe request...")
		conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"))
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			fmt.Printf("[-] Error reading banner: %v\n", err)
		} else if n == 0 {
			fmt.Println("[-] Connection closed by host without returning data.")
		}
	}

	if n > 0 {
		fmt.Printf("\n[+] Raw Response / Banner (%d bytes):\n", n)
		fmt.Println(strings.Repeat("=", 40))
		fmt.Println(string(buf[:n]))
		fmt.Println(strings.Repeat("=", 40))
	} else {
		fmt.Println("[-] No banner data returned (silent service).")
	}
}

func runExplain(args []string) {
	if len(args) < 1 {
		fmt.Println("Error: JSON results file is required. Example: netsage explain results.json")
		os.Exit(1)
	}
	filename := args[0]

	fileData, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("[-] Error reading file %s: %v\n", filename, err)
		os.Exit(1)
	}

	var report ScanReport
	if err := json.Unmarshal(fileData, &report); err != nil {
		fmt.Printf("[-] Error parsing JSON structure: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded scan report for target: %s\n", report.Target)
	fmt.Println("[*] Consulting local AI Explainer (Ollama)...")

	// Prepare prompt text
	var scanSummary []string
	for _, p := range report.Ports {
		scanSummary = append(scanSummary, fmt.Sprintf("- Port %d (%s): %s", p.Port, p.Service, p.Banner))
	}

	prompt := fmt.Sprintf(`You are a SOC analyst assistant. Analyze these scan results for host %s:
%s

Generate a concise report including:
1. Threat Level (Low, Medium, High, Critical)
2. Explanation of open ports and services
3. Practical remediation checklist.`, report.Target, strings.Join(scanSummary, "\n"))

	// Retrieve environment config
	ollamaURL := os.Getenv("OLLAMA_BASE_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	modelName := os.Getenv("OLLAMA_MODEL")
	if modelName == "" {
		modelName = "llama2"
	}

	payload := map[string]interface{}{
		"model":  modelName,
		"prompt": prompt,
		"stream": false,
	}

	jsonPayload, _ := json.Marshal(payload)
	reqURL := fmt.Sprintf("%s/api/generate", ollamaURL)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(reqURL, "application/json", bytes.NewBuffer(jsonPayload))

	if err != nil {
		fmt.Println("[-] Ollama is offline or timed out. Falling back to local offline rules report...")
		printOfflineReport(report)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[-] Ollama returned non-200 code: %d. Falling back to local rules...\n", resp.StatusCode)
		printOfflineReport(report)
		return
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var responseData struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(bodyBytes, &responseData); err != nil {
		fmt.Printf("[-] Error decoding Ollama response JSON: %v\n", err)
		printOfflineReport(report)
		return
	}

	fmt.Println("\n=== AI Threat Explanation Report ===")
	fmt.Println(responseData.Response)
	fmt.Println("=====================================")
}

func printOfflineReport(report ScanReport) {
	fmt.Println("\n=== Local Offline Threat Report (Fallback) ===")
	fmt.Printf("Target Host: %s\n", report.Target)
	fmt.Printf("Scan Time:   %s\n", report.ScanTime)
	fmt.Println(strings.Repeat("-", 45))

	severity := "LOW"
	var recommendations []string

	for _, p := range report.Ports {
		if p.Port == 21 || p.Port == 23 {
			severity = "HIGH"
			recommendations = append(recommendations, fmt.Sprintf("- Port %d (%s) uses an insecure plaintext protocol. Block immediately or transition to SSH/SFTP.", p.Port, p.Service))
		} else if p.Port == 3306 || p.Port == 5432 || p.Port == 1433 {
			if severity != "HIGH" {
				severity = "MEDIUM"
			}
			recommendations = append(recommendations, fmt.Sprintf("- Database port %d (%s) is exposed. Restrict connections to localhost or trusted VPN subnet.", p.Port, p.Service))
		} else if p.Port == 3389 {
			severity = "HIGH"
			recommendations = append(recommendations, "- Remote Desktop (RDP) on 3389 is exposed. Restrict via firewall or enable Multi-Factor Authentication.")
		} else if p.Port == 80 {
			recommendations = append(recommendations, "- Port 80 (HTTP) web traffic is unencrypted. Deploy SSL/TLS certificates and force HTTPS on port 443.")
		}
	}

	fmt.Printf("Calculated Severity: %s\n\n", severity)
	fmt.Println("Remediation Checklist:")
	if len(recommendations) == 0 {
		fmt.Println("- No critical issues found. Maintain regular active scanning cycles.")
	} else {
		for _, rec := range recommendations {
			fmt.Println(rec)
		}
	}
	fmt.Println("===============================================")
}

func getServiceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 1433:
		return "ms-sql-s"
	case 3306:
		// MySQL
		return "mysql"
	case 3389:
		// RDP
		return "ms-wbt-server"
	case 5432:
		// PostgreSQL
		return "postgresql"
	case 8080:
		// HTTP alt
		return "http-alt"
	default:
		return "unknown"
	}
}
