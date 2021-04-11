package main

import (
	"os"
	"runtime/debug"

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

	containername string
	patToken      string
	targetURL     string
	gitHubURL     string
	gitHubRepo    string
	commitSHA     string

	exitCode = -1
)

type token struct {
	Token string
}

func init() {
	arg := os.Args
	containername = arg[1]
	patToken = arg[2]
	targetURL = arg[3]
	gitHubURL = arg[4]
	gitHubRepo = arg[5]
	commitSHA = arg[6]
}

func main() {
	var ghClient GitHubClient

	defer cleanUp(&ghClient)
	printWithColor(colorGreen, "Scanning container image: "+containername+"\n")

	ghClient = NewGitHubAPIClient(patToken, targetURL, gitHubURL, gitHubRepo, commitSHA)
	postGitHubState(ghClient, "pending")

	awsClient := awspkg.NewAWSSDKClient()
	prismasecret := awspkg.GetSecret(awsClient, prismaSecretName, "us-east-1")

	accesskey, secretid := getPrismaKeys(prismasecret)
	token := getAuthToken(accesskey, secretid)

	twistcli := downloadTwistCli(token.Token)

	saveTwistCli(twistcli)

	resultstring := runTwistCli(token.Token, containername)

	scanResult := formatTwistlockResult(resultstring)

	overrides := getOverridesFromAPI()

	scanResult.normalize(overrides)

	exitCode = scanResult.reportToCLI()
}

func postGitHubState(ghClient GitHubClient, state string) {
	_, _, err := CreateRepoStatus(ghClient, state)

	if err != nil {
		printWithColor(colorRed, "Reporting "+state+" to GitHub have failed.", err)
	}
}

func cleanUp(ghClient *GitHubClient) {
	err := recover()
	if err != nil {
		// Panic found, likely an error occurred.
		postGitHubState(*ghClient, "error")
		printWithColor(colorRed, err, string(debug.Stack()))
	} else {
		if exitCode == 0 {
			// Successful run, no volnerabilities were found in a container.
			postGitHubState(*ghClient, "success")
		} else {
			// Not successful run, one or more volnerabilities were found in a container.
			postGitHubState(*ghClient, "failure")
		}
	}

	os.Exit(exitCode)
}
