package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/coryb/sorty"
	"github.com/olekukonko/tablewriter"
)

var (
	cJSON  []map[string]interface{} = nil
	vJSON  []map[string]interface{} = nil
	cTable *tablewriter.Table       = nil
	vTable *tablewriter.Table       = nil
)

func (res ScanResult) reportToCLI(outputFormat int) int {
	var (
		cFound    bool
		cBlocking bool
		vFound    bool
		vBlocking bool
	)

	if outputFormat == OUTPUT_JSON {
		cFound, cBlocking, cJSON = res.ComplianceIssues.prepareJSON()
		vFound, vBlocking, vJSON = res.Vulnerabilities.prepareJSON()
	} else {
		cFound, cBlocking, cTable = res.ComplianceIssues.prepareTable()
		vFound, vBlocking, vTable = res.Vulnerabilities.prepareTable()
	}

	// keep this outside of if/else block above, since printWithColor checks output format
	// also, we need this block here to ensure the correct return code
	if cBlocking || vBlocking {
		printWithColor(colorRed, "\nFAILED : Blocking issue(s) reported with the Image.")
		return EXIT_FAILURE
	} else {
		if cFound || vFound {
			printWithColor(colorYellow, "\nWARNING : Issue(s) reported with the Image.")
		} else {
			printWithColor(colorGreen, "\nSUCCESS : No issue(s) reported with the Image.")
		}
	}
	return EXIT_SUCCESS
}

func outputResults() {
	var (
		jsonOutput []byte
		err        error
	)

	if outputFormat == OUTPUT_JSON {
		combined := mergeJSON(cJSON, vJSON)
		jsonOutput, err = json.MarshalIndent(combined, "", "  ")
		if err != nil {
			panic(debug.Stack())
		} else {
			fmt.Println(string(jsonOutput))
		}
	} else if outputFormat == OUTPUT_TABLE {
		printWithColor(colorRed, "Compliance Issues:")
		cTable.Render()
		printWithColor(colorRed, "Vulnerabilities:")
		vTable.Render()
	}
}

func mergeJSON(cJSON []map[string]interface{}, vJSON []map[string]interface{}) map[string]interface{} {
	// if no vulnerabilities/compliance issues are found, the corresponding field is set to `null`
	combinedJSON := map[string]interface{}{
		"complianceIssues": cJSON,
		"vulnerabilities":  vJSON,
		"debugMessages":    debugMessages,
	}
	return combinedJSON
}

func (comp ComplianceIssues) prepareTable() (bool, bool, *tablewriter.Table) {
	table := tablewriter.NewWriter(os.Stdout)
	blocking := false

	table.SetHeader([]string{"Id", "Severity", "Title", "Cause"})
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
	)
	for _, c := range comp {
		if c["block"] != nil {
			blocking = true
		}
		table.Append([]string{
			c["cpl"].(string),
			c["severity"].(string),
			c["title"].(string),
			c["cause"].(string),
		})
	}

	return len(comp) > 0, blocking, table
}

func (comp ComplianceIssues) prepareJSON() (bool, bool, []map[string]interface{}) {
	blocking := false
	filteredIssues := make([]map[string]interface{}, 0)

	for _, c := range comp {
		if c["block"] != nil {
			blocking = true
		}

		filteredIssues = append(filteredIssues, map[string]interface{}{
			"Id":       c["cpl"].(string),
			"Severity": c["severity"].(string),
			"Title":    c["title"].(string),
			"Cause":    c["cause"].(string),
		})
	}

	return len(comp) > 0, blocking, filteredIssues
}

func (vuln Vulnerabilities) prepareTable() (bool, bool, *tablewriter.Table) {
	blocking := false
	table := tablewriter.NewWriter(os.Stdout)

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

	s := sorty.NewSorter().ByKeys([]string{
		"-cvss",
		"+packageName",
	})

	s.Sort(vuln)

	for _, v := range vuln {
		if v["block"] != nil {
			blocking = true
		}
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

	return len(vuln) > 0, blocking, table
}

func (vuln Vulnerabilities) prepareJSON() (bool, bool, []map[string]interface{}) {
	blocking := false
	filteredIssues := make([]map[string]interface{}, 0)

	s := sorty.NewSorter().ByKeys([]string{
		"-cvss",
		"+packageName",
	})
	s.Sort(vuln)

	for _, v := range vuln {
		if v["block"] != nil {
			blocking = true
		}
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
	}

	return len(vuln) > 0, blocking, filteredIssues
}

func printWithColor(color string, str ...interface{}) {
	// if outputFormat is "json", do not print anything, but add it to the debugMessages list (to be reported later)
	// outputFormat is defined at a package-global level in `scan.go`
	if outputFormat == OUTPUT_JSON {
		thisMessage := ""
		for _, v := range str {
			thisMessage += fmt.Sprintf("%s ", v)
		}
		thisMessage = strings.TrimSpace(thisMessage)
		debugMessages = append(debugMessages, thisMessage)
	} else {
		fmt.Print(color)
		for _, v := range str {
			fmt.Println(v)
		}
		fmt.Print(colorReset)
	}
}
