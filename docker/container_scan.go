package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/olekukonko/tablewriter"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"

	CONSOLEURI = "https://us-east1.cloud.twistlock.com/us-2-158254964"

	accesskey string
	secretid  string
	container string
)

type token struct {
	Token string
}

type ScanResult struct {
	ComplianceIssues
	Vulnerabilities
}

type ComplianceIssues []map[string]interface{}
type Vulnerabilities []map[string]interface{}

func init() {
	arg := os.Args
	accesskey = arg[1]
	secretid = arg[2]
	container = arg[3]
}

func getAuthToken(username string, password string) token {

	url := CONSOLEURI + "/api/v1/authenticate"

	postBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, bytes.NewReader(postBody))
	req.Header.Add("content-type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		println(err.Error()) // handle error
	}
	defer resp.Body.Close()

	// r = requests.post(
	// url, headers={"content-type": "application/json"}, data=respo
	// token = r.json()["token"]
	body, _ := ioutil.ReadAll(resp.Body)
	tokenjson := string(body)
	var token token
	json.Unmarshal([]byte(tokenjson), &token)
	return token
}

func getAPIResponse(url string, authToken string) []byte {
	var body []byte
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 2 * time.Minute

	client := &http.Client{}
	var resp *http.Response
	var err error
	var apierror error
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+authToken)

	err = backoff.Retry(func() error {
		resp, apierror = client.Do(req)
		if apierror != nil {
			return apierror
		}
		defer resp.Body.Close()
		apibody, readerror := ioutil.ReadAll(resp.Body)
		if apierror != nil {
			return readerror
		}
		body = apibody
		return nil
	}, bo)

	if err != nil {
		println(err.Error()) // handle error
	}
	return body
}

func downloadTwistCli(token string) {
	twistcli := getAPIResponse(CONSOLEURI+"/api/v1/util/twistcli", token)

	err := ioutil.WriteFile("twistcli", twistcli, 0755)
	if err != nil {
		println("error saving twistcli")
		println(err.Error()) // handle error
	}
}

func runTwistCli(token string, container string) string {
	cmd := exec.Command("/bin/sh", "-c", "./twistcli images scan --details --address "+CONSOLEURI+" --token "+token+" --ci "+container)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		printWithColor(colorRed, "Error : Unexpected error while executing twistlock cli", err, stderr.String())
		os.Exit(1)
	}

	return out.String()
}

func formatTwistlockResult(resultstring string) ScanResult {
	delimiter := "====DATA"
	res := resultstring[strings.Index(resultstring, delimiter)+len(delimiter):]

	s := []struct {
		EntityInfo ScanResult
	}{}

	if err := json.Unmarshal([]byte(res), &s); err != nil {
		printWithColor(colorRed, "Error : Unable to unmarshal twistlock result", err)
		os.Exit(1)
	}

	return s[0].EntityInfo
}

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

func main() {
	printWithColor(colorGreen, "Container Scanner Started\n")

	token := getAuthToken(accesskey, secretid)

	downloadTwistCli(token.Token)

	resultstring := runTwistCli(token.Token, container)
	scanResult := formatTwistlockResult(resultstring)

	scanResult.normalize()

	scanResult.reportToCLI()
}
