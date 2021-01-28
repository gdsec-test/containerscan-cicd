package main

import "fmt"

func (res *ScanResult) normalize() {
	res.ComplianceIssues.normalize()
	res.Vulnerabilities.normalize()
	fmt.Println("")
}

func (comp *ComplianceIssues) normalize() {
	printWithColor(colorBlue, "ComplianceIssues Normalization Not Implemented.")
}

func (vuln *Vulnerabilities) normalize() {
	printWithColor(colorBlue, "Vulnerabilities Normalization Not Implemented.")
}
