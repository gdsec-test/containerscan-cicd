package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
)

func (res ScanResult) reportToCLI() {
	cFound := res.ComplianceIssues.reportToCLI()
	fmt.Println()
	vFound := res.Vulnerabilities.reportToCLI()

	if cFound || vFound {
		printWithColor(colorRed, "\nFAILED : Above issue(s) found with the Image.")
		os.Exit(1)
	} else {
		printWithColor(colorGreen, "\nSUCCESS : Could not find any issue(s) with the Image.")
	}
}

func (comp ComplianceIssues) reportToCLI() bool {
	if len(comp) == 0 {
		return false
	}

	printWithColor(colorRed, "Compliance Issues :")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Severity", "Title", "Description", "Type"})
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold})

	for _, c := range comp {
		table.Append([]string{
			strconv.FormatFloat(c["id"].(float64), 'f', 0, 64),
			c["severity"].(string),
			c["title"].(string),
			c["description"].(string),
			c["type"].(string),
		})
	}

	table.Render()

	return true
}

func (vuln Vulnerabilities) reportToCLI() bool {
	if len(vuln) == 0 {
		return false
	}

	printWithColor(colorRed, "Vulnerability Issues :")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"CVE",
		"CVSS",
		"Severity",
		"Status",
		"Package Name",
		"Package Version",
		"Description",
		"Type",
		"Link",
	})
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold})

	for _, v := range vuln {
		table.Append([]string{
			v["cve"].(string),
			strconv.FormatFloat(v["cvss"].(float64), 'f', 2, 64),
			v["severity"].(string),
			v["status"].(string),
			v["packageName"].(string),
			v["packageVersion"].(string),
			v["description"].(string),
			v["type"].(string),
			"https://web.nvd.nist.gov/view/vuln/detail?vulnId=" + v["cve"].(string),
		})
	}

	table.Render()

	return true
}

func printWithColor(color string, str ...interface{}) {
	fmt.Print(color)
	for _, v := range str {
		fmt.Println(v)
	}
	fmt.Print(colorReset)
}
