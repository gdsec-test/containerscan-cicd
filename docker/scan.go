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
	printWithColor(colorGreen, "Container Scanner Started\n")

	accesskey, secretid := getPrismaSecret()

	token := getAuthToken(accesskey, secretid)

	downloadTwistCli(token.Token)

	resultstring := runTwistCli(token.Token, containername)
	fmt.Println("")

	scanResult := formatTwistlockResult(resultstring)

	scanResult.normalize()
	scanResult.reportToCLI()
}
