package main

import (
	"os"
	"runtime/debug"
	"strings"

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

	postGithubStatus = true
	exitCode         = -1
)

type token struct {
	Token string
}

func init() {
	arg := os.Args
	containername = arg[1]
	argCount := len(os.Args)
	if argCount < 3 || argCount > 7 || (arg[2] != "nostatus" && (arg[2] == "" || arg[3] == "" || arg[4] == "" || arg[5] == "" || arg[6] == "")) {
		printWithColor(colorRed, "Required GitHub args not provided", "You should provide `nostatus` as 2nd arg or 5 args for GitHub status report")
		os.Exit(exitCode)
	}

	patToken = arg[2]
	targetURL = arg[3]
	gitHubURL = arg[4]
	gitHubRepo = arg[5]
	commitSHA = arg[6]

	if strings.ToLower(patToken) == "nostatus" {
		printWithColor(colorYellow, "Running scanner without GitHub status report")
		postGithubStatus = false
	} else {
		printWithColor(colorGreen, "Running scanner with GitHub status report")
	}
}

func main() {
	printWithColor(colorGreen, "Scanning container image: "+containername+"\n")

	var ghClient GitHubClient
	if postGithubStatus {
		ghClient = NewGitHubAPIClient(patToken, targetURL, gitHubURL, gitHubRepo, commitSHA)
		postGitHubState(ghClient, "pending")
		defer cleanUpAndPostGithubStatus(&ghClient)
	}

	awsClient := awspkg.NewAWSSDKClient()
	prismasecret := awspkg.GetSecretFromS3(awsClient, "gd-security-prod-container-scanner-storage", "prisma-secret.json", "us-east-1")

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

func cleanUpAndPostGithubStatus(ghClient *GitHubClient) {
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
