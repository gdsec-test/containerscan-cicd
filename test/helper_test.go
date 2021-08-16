package test

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

type DebugMessage string

type ComplianceIssue struct {
	Cause    string `json:Cause`
	Id       string `json:Id`
	Severity string `json:Severity`
	Title    string `json:Title`
}

type Vulnerability struct {
	CVE            string `json:CVE`
	CVSS           string `json:CVSS`
	FixedOn        string `json:Fixed On`
	Link           string `json:Link`
	PackageName    string `json:Package Name`
	PackageType    string `json:Package Type`
	PackageVersion string `json:Package Version`
	Severity       string `json:Severity`
	Status         string `json:Status`
}

type JSONOutput struct {
	ComplianceIssues []ComplianceIssue `json:complianceIssues`
	DebugMessages    []DebugMessage    `json:debugMessages`
	Vulnerabilities  []Vulnerability   `json:vulnerabilities`
}

func convertJSON(output string) JSONOutput {
	var res JSONOutput
	err := json.Unmarshal([]byte(output), &res)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func assertExitCodeEqual(actual int, expected int) (bool, string) {
	if actual != expected {
		return false, fmt.Sprintf("Expected exitcode to be %d, but got %d instead.", expected, actual)
	}
	return true, fmt.Sprintf("Expected exitcode to be %d, and got %d.", expected, actual)
}

func assertContains(output string, substr string) (bool, string) {
	if !strings.Contains(output, substr) {
		return false, fmt.Sprintf("Expected '%s' to be in the output, but not found.", substr)
	}
	return true, fmt.Sprintf("Expected '%s' to be in the output, and found.", substr)
}

func assertNotContains(output string, substr string) (bool, string) {
	if strings.Contains(output, substr) {
		return false, fmt.Sprintf("Expected '%s' to not be in the output, but was found.", substr)
	}
	return true, fmt.Sprintf("Expected '%s' to not be in the output, and was not found.", substr)
}

func assertComplianceEmpty(cis []ComplianceIssue) (bool, string) {
	if len(cis) != 0 {
		return false, fmt.Sprintf("Expected '%#v' to be empty, but was not empty.", cis)
	}
	return true, fmt.Sprintf("Expected '%#v' to be empty, and was empty.", cis)
}

func assertComplianceNotEmpty(cis []ComplianceIssue) (bool, string) {
	if len(cis) != 0 {
		return true, fmt.Sprintf("Expected '%#v' to not be empty, and was not empty.", cis)
	}
	return false, fmt.Sprintf("Expected '%#v' to not be empty, but was empty.", cis)
}

func assertVulnerabilityEmpty(vulns []Vulnerability) (bool, string) {
	if len(vulns) != 0 {
		return false, fmt.Sprintf("Expected '%#v' to be empty, but was not empty.", vulns)
	}
	return true, fmt.Sprintf("Expected '%#v' to be empty, and was empty.", vulns)
}

func assertVulnerabilityNotEmpty(vulns []Vulnerability) (bool, string) {
	if len(vulns) != 0 {
		return true, fmt.Sprintf("Expected '%#v' to not be empty, and was not empty.", vulns)
	}
	return false, fmt.Sprintf("Expected '%#v' to not be empty, but was empty.", vulns)
}

func assertDebugMessageContains(debugMessages []DebugMessage, substr string) (bool, string) {
	for _, m := range debugMessages {
		if strings.Contains(string(m), substr) {
			return true, fmt.Sprintf("Expected '%s' to be in the DebugMessages, and found.", substr)
		}
	}
	return false, fmt.Sprintf("Expected '%s' to be in the DebugMessages, but was not found.", substr)
}

func assertDebugMessageNotContains(debugMessages []DebugMessage, substr string) (bool, string) {
	for _, m := range debugMessages {
		if strings.Contains(string(m), substr) {
			return false, fmt.Sprintf("Expected '%s' to not be in the DebugMessages, but was found.", substr)
		}
	}
	return true, fmt.Sprintf("Expected '%s' to not be in the DebugMessages, and was not found.", substr)
}
