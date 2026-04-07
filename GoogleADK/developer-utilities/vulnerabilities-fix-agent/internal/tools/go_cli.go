package tools

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/adk/tool"
)

type DirArgs struct {
	Path string `json:"path" description:"The absolute path to the project directory"`
}

type Vulnerability struct {
	Name     string
	Severity string
}

func InstallOSVScanner(tc tool.Context, args DirArgs) (string, error) {
	// Check if osv-scanner is already installed
	if _, err := exec.LookPath("osv-scanner"); err == nil {
		return "OSV Scanner is already installed.", nil
	}

	fmt.Println("[System] Installing OSV Scanner...")

	// Install osv-scanner using go install
	cmd := exec.Command("go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest")
	cmd.Dir = args.Path
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to install OSV Scanner: %s", string(out))
	}

	// Verify installation
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		return "", fmt.Errorf("OSV Scanner installation failed - not found in PATH")
	}

	return "OSV Scanner installed successfully.", nil
}

func ScanWithOSVScanner(tc tool.Context, args DirArgs) (string, error) {
	// Check if project has already been fixed (post-fix CSV exists and is empty)
	postFixCSV := filepath.Join(args.Path, "post_fix_vulnerabilities_report.csv")
	if _, err := os.Stat(postFixCSV); err == nil {
		// File exists, check if it's empty (no vulnerabilities)
		content, err := os.ReadFile(postFixCSV)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			// CSV should have header + data rows. If only header exists, project is fixed
			if len(lines) <= 1 || (len(lines) == 2 && strings.TrimSpace(lines[1]) == "") {
				return fmt.Sprintf("Project %s has already been fixed. No vulnerabilities remain.\n📄 Previous post-fix report: %s", args.Path, postFixCSV), nil
			}
		}
	}

	// First ensure osv-scanner is installed
	installResult, err := InstallOSVScanner(tc, args)
	if err != nil {
		return "", fmt.Errorf("OSV Scanner installation failed: %v", err)
	}
	if !strings.Contains(installResult, "already installed") {
		fmt.Println(installResult)
	}

	// Run osv-scanner
	cmd := exec.Command("osv-scanner", "scan", ".")
	cmd.Dir = args.Path
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("failed to run OSV Scanner: %v", err)
	}

	return string(out), nil
}

func GenerateOSVCSV(tc tool.Context, args DirArgs) (string, error) {
	// Check if project has already been fixed (post-fix CSV exists and is empty)
	postFixCSV := filepath.Join(args.Path, "post_fix_vulnerabilities_report.csv")
	if _, err := os.Stat(postFixCSV); err == nil {
		// File exists, check if it's empty (no vulnerabilities)
		content, err := os.ReadFile(postFixCSV)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			// CSV should have header + data rows. If only header exists, project is fixed
			// Empty file or file with only header means no vulnerabilities
			if len(lines) <= 1 || (len(lines) == 2 && strings.TrimSpace(lines[1]) == "") {
				return fmt.Sprintf("✅ Project %s has already been fixed. No vulnerabilities remain.\n📄 Previous post-fix report: %s", args.Path, postFixCSV), nil
			}
		}
	}

	// Get OSV scan results
	scanResult, err := ScanWithOSVScanner(tc, args)
	if err != nil {
		return "", err
	}

	// Parse OSV output and generate CSV
	vulnerabilities := parseOSVVulnerabilities(scanResult)
	if len(vulnerabilities) == 0 {
		return fmt.Sprintf("✅ No vulnerabilities found in %s via OSV Scanner. Project is already clean. No report generated.", args.Path), nil
	}

	// Generate CSV file
	csvPath := filepath.Join(args.Path, "osv_vulnerabilities_report.csv")
	err = writeCSV(csvPath, vulnerabilities)
	if err != nil {
		return "", fmt.Errorf("failed to write OSV CSV: %v", err)
	}

	return fmt.Sprintf("Generated OSV vulnerability report: %s (%d vulnerabilities found)", csvPath, len(vulnerabilities)), nil
}

func ScanVulnerabilities(tc tool.Context, args DirArgs) (string, error) {
	// Check if project has already been fixed (post-fix CSV exists and is empty)
	postFixCSV := filepath.Join(args.Path, "post_fix_vulnerabilities_report.csv")
	if _, err := os.Stat(postFixCSV); err == nil {
		// File exists, check if it's empty (no vulnerabilities)
		content, err := os.ReadFile(postFixCSV)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			// CSV should have header + data rows. If only header exists, project is fixed
			if len(lines) <= 1 || (len(lines) == 2 && strings.TrimSpace(lines[1]) == "") {
				return fmt.Sprintf("✅ Project %s has already been fixed. No vulnerabilities remain.\n📄 Previous post-fix report: %s", args.Path, postFixCSV), nil
			}
		}
	}

	cmd := exec.Command("govulncheck", "./...")
	cmd.Dir = args.Path
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("failed to run govulncheck: %v", err)
	}
	return string(out), nil
}

func GenerateVulnerabilityCSV(tc tool.Context, args DirArgs) (string, error) {
	// Check if project has already been fixed (post-fix CSV exists and is empty)
	postFixCSV := filepath.Join(args.Path, "post_fix_vulnerabilities_report.csv")
	if _, err := os.Stat(postFixCSV); err == nil {
		// File exists, check if it's empty (no vulnerabilities)
		content, err := os.ReadFile(postFixCSV)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			// CSV should have header + data rows. If only header exists, project is fixed
			// Empty file or file with only header means no vulnerabilities
			if len(lines) <= 1 || (len(lines) == 2 && strings.TrimSpace(lines[1]) == "") {
				return fmt.Sprintf("✅ Project %s has already been fixed. No vulnerabilities remain.\n📄 Previous post-fix report: %s", args.Path, postFixCSV), nil
			}
		}
	}

	// Run govulncheck to get vulnerabilities
	cmd := exec.Command("govulncheck", "./...")
	cmd.Dir = args.Path
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("failed to run govulncheck: %v", err)
	}

	// Parse vulnerabilities from output
	vulnerabilities := parseVulnerabilities(string(out))
	if len(vulnerabilities) == 0 {
		return fmt.Sprintf("✅ No vulnerabilities found in %s. Project is already clean. No report generated.", args.Path), nil
	}

	// Generate CSV file
	csvPath := filepath.Join(args.Path, "vulnerabilities_report.csv")
	err = writeCSV(csvPath, vulnerabilities)
	if err != nil {
		return "", fmt.Errorf("failed to write CSV: %v", err)
	}

	return fmt.Sprintf("Generated vulnerability report: %s (%d vulnerabilities found)", csvPath, len(vulnerabilities)), nil
}

func ApplyFixes(tc tool.Context, args DirArgs) (string, error) {
	// Run go get -u to upgrade vulnerable dependencies
	get := exec.Command("go", "get", "-u", "./...")
	get.Dir = args.Path  // ← THIS WAS MISSING! It was running in wrong directory
	getOut, getErr := get.CombinedOutput()
	if getErr != nil {
		return "", fmt.Errorf("failed to upgrade dependencies: %s", string(getOut))
	}

	// Run go mod tidy to clean up
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = args.Path
	tidyOut, tidyErr := tidy.CombinedOutput()
	if tidyErr != nil {
		return "", fmt.Errorf("failed to tidy: %s", string(tidyOut))
	}

	return fmt.Sprintf("Dependencies upgraded and go.mod updated in: %s\nChanges:\n%s", args.Path, string(getOut)), nil
}

func GeneratePostFixCSV(tc tool.Context, args DirArgs) (string, error) {
	// Run govulncheck again after fixes
	cmd := exec.Command("govulncheck", "./...")
	cmd.Dir = args.Path
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("failed to run govulncheck: %v", err)
	}

	// Parse remaining vulnerabilities
	vulnerabilities := parseVulnerabilities(string(out))

	// Generate CSV file
	csvPath := filepath.Join(args.Path, "post_fix_vulnerabilities_report.csv")
	err = writeCSV(csvPath, vulnerabilities)
	if err != nil {
		return "", fmt.Errorf("failed to write CSV: %v", err)
	}

	if len(vulnerabilities) == 0 {
		return fmt.Sprintf("All vulnerabilities fixed! Report: %s (empty)", csvPath), nil
	}

	return fmt.Sprintf("Generated post-fix report: %s (%d vulnerabilities remaining)", csvPath, len(vulnerabilities)), nil
}

func ValidateBuild(tc tool.Context, args DirArgs) (string, error) {
	cmd := exec.Command("go", "test", "./...")
	cmd.Dir = args.Path
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("TEST REGRESSION DETECTED:\n%s", string(out)), nil
	}
	return "TESTS PASSED: Build is stable.", nil
}

func parseVulnerabilities(output string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Split output into lines
	lines := strings.Split(output, "\n")

	// Look for vulnerability patterns
	// govulncheck output typically contains lines like:
	// "Vulnerability #1: GO-2023-1234"
	// "  Severity: HIGH"
	// "  Package: example.com/package"

	vulnRegex := regexp.MustCompile(`Vulnerability #\d+:\s*(GO-\d+-\d+)`)
	severityRegex := regexp.MustCompile(`Severity:\s*(\w+)`)

	var currentVuln *Vulnerability

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for vulnerability ID
		if vulnMatch := vulnRegex.FindStringSubmatch(line); len(vulnMatch) > 1 {
			if currentVuln != nil {
				vulnerabilities = append(vulnerabilities, *currentVuln)
			}
			currentVuln = &Vulnerability{Name: vulnMatch[1], Severity: "UNKNOWN"} // Default severity
		}

		// Check for severity
		if severityMatch := severityRegex.FindStringSubmatch(line); len(severityMatch) > 1 && currentVuln != nil {
			currentVuln.Severity = strings.ToUpper(severityMatch[1])
		}
	}

	// Add the last vulnerability if exists
	if currentVuln != nil {
		vulnerabilities = append(vulnerabilities, *currentVuln)
	}

	return vulnerabilities
}

func writeCSV(filePath string, vulnerabilities []Vulnerability) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	err = writer.Write([]string{"Serial Number", "Vulnerability Name", "Vulnerability Severity"})
	if err != nil {
		return err
	}

	// Write data
	for i, vuln := range vulnerabilities {
		severity := vuln.Severity
		if severity == "" {
			severity = "UNKNOWN"
		}
		severity = strings.ToUpper(severity)

		err = writer.Write([]string{
			strconv.Itoa(i + 1),
			vuln.Name,
			severity,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func parseOSVVulnerabilities(output string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// OSV scanner output format is different from govulncheck
	// It typically shows vulnerabilities in a structured format
	lines := strings.Split(output, "\n")

	// Look for vulnerability patterns in OSV output
	// OSV format: "GHSA-xxxx-xxxx-xxxx" or "GO-2023-xxxx"
	osvRegex := regexp.MustCompile(`(GHSA-[a-zA-Z0-9-]+|GO-\d{4}-\d{4})`)
	severityRegex := regexp.MustCompile(`(?i)severity:\s*(critical|high|medium|low|info)`)

	var currentVuln *Vulnerability

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for vulnerability ID
		if vulnMatch := osvRegex.FindStringSubmatch(line); len(vulnMatch) > 1 {
			if currentVuln != nil {
				vulnerabilities = append(vulnerabilities, *currentVuln)
			}
			currentVuln = &Vulnerability{Name: vulnMatch[1], Severity: "UNKNOWN"} // Default severity
		}

		// Check for severity
		if severityMatch := severityRegex.FindStringSubmatch(line); len(severityMatch) > 1 && currentVuln != nil {
			currentVuln.Severity = strings.ToUpper(severityMatch[1])
		}
	}

	// Add the last vulnerability if exists
	if currentVuln != nil {
		vulnerabilities = append(vulnerabilities, *currentVuln)
	}

	return vulnerabilities
}
