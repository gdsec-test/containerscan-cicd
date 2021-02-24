package main

import (
	"fmt"
	"os"
)

//ScanResult scan result with compliance and vulnerability findinds
type ScanResult struct {
	ComplianceIssues
	Vulnerabilities
}

//ComplianceIssues List of compliance findinds
type ComplianceIssues []map[string]interface{}

//Vulnerabilities List of vulnerability findinds
type Vulnerabilities []map[string]interface{}

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"

	prismaSecretName = "PrismaAccessKeys"
	prismaConsoleURL = "https://us-east1.cloud.twistlock.com/us-2-158254964"

	accesskey     string
	secretid      string
	containername string
)

type token struct {
	Token string
}

func init() {
	arg := os.Args
	containername = arg[1]

}

func main() {
	printWithColor(colorGreen, "Scanning container image: "+containername+"\n")

	prismasecret := getSecret(prismaSecretName, "us-east-1")
	accesskey, secretid := getPrismaKeys(prismasecret)
	token := getAuthToken(accesskey, secretid)

	twistcli := downloadTwistCli(token.Token)

	saveTwistCli(twistcli)

	resultstring := runTwistCli(token.Token, containername)
	fmt.Println("")

	scanResult := formatTwistlockResult(resultstring)

	overrides := getOverridesFromAPI()

	scanResult.normalize(overrides)
	scanResult.reportToCLI()
}
