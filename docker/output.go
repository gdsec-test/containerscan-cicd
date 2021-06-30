package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/coryb/sorty"
	"github.com/olekukonko/tablewriter"
)

func (res ScanResult) reportToCLI() int {
	cFound, cBlocking := res.ComplianceIssues.reportToCLI()

	vFound, vBlocking := res.Vulnerabilities.reportToCLI()

	if cBlocking || vBlocking {
		printWithColor(colorRed, "\nFAILED : Blocking issue(s) reported with the Image.")
		return 1
	} else {
		if cFound || vFound {
			printWithColor(colorYellow, "\nWARNING : Issue(s) reported with the Image.")
		} else {
			printWithColor(colorGreen, "\nSUCCESS : No issue(s) reported with the Image.")
		}
	}
	return 0
}

func (comp ComplianceIssues) reportToCLI() (bool, bool) {
	if len(comp) == 0 {
		return false, false
	}

	printWithColor(colorRed, "Compliance Issues :")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Severity", "Title"})
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		// tablewriter.Colors{tablewriter.Bold},
		// tablewriter.Colors{tablewriter.Bold}
	)
	blocking := false
	for _, c := range comp {
		// sup := ""
		// if c["SUPPRESS"] != nil {
		// sup = "SUPPRESS"
		// }
		if c["block"] != nil {
			blocking = true
		}
		table.Append([]string{
			c["cpl"].(string),
			c["severity"].(string),
			c["title"].(string),
			// c["type"].(string),
			// sup,
		})
	}

	table.Render()

	return true, blocking
}

func (vuln Vulnerabilities) reportToCLI() (bool, bool) {
	if len(vuln) == 0 {
		return false, false
	}

	s := sorty.NewSorter().ByKeys([]string{
		"-cvss",
		"+packageName",
	})

	s.Sort(vuln)

	printWithColor(colorRed, "Vulnerability Issues :")
	blocking := false
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"CVE",
		"CVSS",
		"Severity",
		"Status",
		"Package Name",
		"Package Version",
		// "Description",
		// "Type",
		"Link",
		// "SUPPRESS",
	})
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		// tablewriter.Colors{tablewriter.Bold},
		// tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold})

	for _, v := range vuln {
		// sup := ""
		// if v["SUPPRESS"] != nil {
		// sup = "SUPPRESS"
		// }
		if v["block"] != nil {
			blocking = true
		}
		table.Append([]string{
			v["cve"].(string),
			strconv.FormatFloat(v["cvss"].(float64), 'f', 2, 64),
			v["severity"].(string),
			v["status"].(string),
			v["packageName"].(string),
			v["packageVersion"].(string),
			// v["description"].(string),
			"https://web.nvd.nist.gov/view/vuln/detail?vulnId=" + v["cve"].(string),
		})
	}

	table.Render()

	return true, blocking
}

func printWithColor(color string, str ...interface{}) {
	fmt.Print(color)
	for _, v := range str {
		fmt.Println(v)
	}
	fmt.Print(colorReset)
}
