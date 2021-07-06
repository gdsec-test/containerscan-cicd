package main

import (
	"encoding/json"
	"fmt"
	"github.com/coryb/sorty"
	"github.com/olekukonko/tablewriter"
	"os"
	"strconv"
	"time"
)

func (res ScanResult) reportToCLI(outputFormat string) int {
	cFound, cBlocking := res.ComplianceIssues.reportToCLI(outputFormat)

	vFound, vBlocking := res.Vulnerabilities.reportToCLI(outputFormat)

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

func (comp ComplianceIssues) reportToCLI(outputFormat string) (bool, bool) {
	if len(comp) == 0 {
		return false, false
	}
	blocking := false
	printWithColor(colorRed, "Compliance Issues :")
	filteredIssues := make([]map[string]interface{}, 0)
	table := tablewriter.NewWriter(os.Stdout)
	if outputFormat != "json" {
		table.SetHeader([]string{"Id", "Severity", "Title", "Cause"})
		table.SetRowLine(true)
		table.SetRowSeparator("-")
		table.SetHeaderColor(
			tablewriter.Colors{tablewriter.Bold},
			tablewriter.Colors{tablewriter.Bold},
			tablewriter.Colors{tablewriter.Bold},
			tablewriter.Colors{tablewriter.Bold},
		)
	}
	for _, c := range comp {
		if c["block"] != nil {
			blocking = true
		}
		if outputFormat == "json" {
			filteredIssues = append(filteredIssues, map[string]interface{}{
				"Id":       c["cpl"].(string),
				"Severity": c["severity"].(string),
				"Title":    c["title"].(string),
				"Cause":    c["cause"].(string),
			})
		} else {
			table.Append([]string{
				c["cpl"].(string),
				c["severity"].(string),
				c["title"].(string),
				c["cause"].(string),
			})
		}
	}

	if outputFormat == "json" {
		json, _ := json.MarshalIndent(filteredIssues, "", "  ")
		fmt.Println(string(json))
	} else {
		table.Render()
	}

	return true, blocking
}

func (vuln Vulnerabilities) reportToCLI(outputFormat string) (bool, bool) {
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

	filteredIssues := make([]map[string]interface{}, 0)
	table := tablewriter.NewWriter(os.Stdout)
	if outputFormat != "json" {
		table.SetHeader([]string{
			"CVE",
			"CVSS",
			"Severity",
			"Package Type",
			"Package Name",
			"Package Version",
			"Status",
			"Fixed On",
			"Link",
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
			tablewriter.Colors{tablewriter.Bold},
			tablewriter.Colors{tablewriter.Bold},
			tablewriter.Colors{tablewriter.Bold})
	}

	for _, v := range vuln {
		if v["block"] != nil {
			blocking = true
		}
		if outputFormat == "json" {
			filteredIssues = append(filteredIssues, map[string]interface{}{
				"CVE":             v["cve"].(string),
				"CVSS":            strconv.FormatFloat(v["cvss"].(float64), 'f', 2, 64),
				"Severity":        v["severity"].(string),
				"Package Type":    v["packageType"].(string),
				"Package Name":    v["packageName"].(string),
				"Package Version": v["packageVersion"].(string),
				"Status":          v["status"].(string),
				"Fixed On":        time.Unix(int64(v["fixDate"].(float64)), 0).Format(time.RFC822),
				"Link":            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=" + v["cve"].(string),
			})
		} else {
			table.Append([]string{
				v["cve"].(string),
				strconv.FormatFloat(v["cvss"].(float64), 'f', 2, 64),
				v["severity"].(string),
				v["packageType"].(string),
				v["packageName"].(string),
				v["packageVersion"].(string),
				v["status"].(string),
				time.Unix(int64(v["fixDate"].(float64)), 0).Format(time.RFC822),
				"https://web.nvd.nist.gov/view/vuln/detail?vulnId=" + v["cve"].(string),
			})
		}
	}

	if outputFormat == "json" {
		json, _ := json.MarshalIndent(filteredIssues, "", "  ")
		fmt.Println(string(json))
	} else {
		table.Render()
	}

	return true, blocking
}

func printWithColor(color string, str ...interface{}) {
	fmt.Print(color)
	for _, v := range str {
		fmt.Println(v)
	}
	fmt.Print(colorReset)
}
