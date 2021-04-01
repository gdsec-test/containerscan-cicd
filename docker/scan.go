package main

import (
	"fmt"
	"os"

	"github.com/gdcorp-infosec/containerscan-cicd/docker/awspkg"
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

	c := awspkg.NewAWSSDKClient()
	prismasecret := awspkg.GetSecret(c, prismaSecretName, "us-east-1")
	fmt.Println("Getting secret")
	accesskey, secretid := getPrismaKeys(prismasecret)
	token := getAuthToken(accesskey, secretid)
	fmt.Println("Getting token")
	twistcli := downloadTwistCli(token.Token)
	fmt.Println("download cli")
	saveTwistCli(twistcli)
	fmt.Println("save cli")
	resultstring := runTwistCli(token.Token, containername)
	fmt.Println("run cli")
	scanResult := formatTwistlockResult(resultstring)

	overrides := getOverridesFromAPI()

	scanResult.normalize(overrides)
	scanResult.reportToCLI()
}
