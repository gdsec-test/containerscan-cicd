package main

import (
	"fmt"
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

	containername      string
	patToken           string
	targetURL          string
	gitHubURL          string
	gitHubRepo         string
	commitSHA          string
	awsDefaultRegion string

	outputFormat = "table"

	postGithubStatus = true
	exitCode         = -1
)

type token struct {
	Token string
}

func checkRequiredEnvVariable(name string) {
	if os.Getenv(name) == "" {
		printWithColor(colorRed, fmt.Sprintf("Required Environment variable %s is not provided\n", name))
		os.Exit(exitCode)
	}
}

func init() {
	arg := os.Args
	for _, currentArg := range arg {
		if strings.HasPrefix(currentArg, "container=") {
			containername = strings.Split(currentArg, "=")[1]
		}
		if strings.HasPrefix(currentArg, "githubtoken=") {
			patToken = strings.Split(currentArg, "=")[1]
		}
		if strings.HasPrefix(currentArg, "format=") {
			outputFormat = strings.Split(currentArg, "=")[1] // optional output parameter, table or json
		}
		if strings.HasPrefix(currentArg, "status=") && strings.HasSuffix(currentArg, "=nostatus") {
			postGithubStatus = false
		}
		if strings.HasPrefix(currentArg, "targeturl=") {
			targetURL = strings.Split(currentArg, "=")[1]
		}
		if strings.HasPrefix(currentArg, "githuburl=") {
			gitHubURL = strings.Split(currentArg, "=")[1]
		}
		if strings.HasPrefix(currentArg, "repo=") {
			gitHubRepo = strings.Split(currentArg, "=")[1]
		}
		if strings.HasPrefix(currentArg, "commit=") {
			commitSHA = strings.Split(currentArg, "=")[1]
		}
		if strings.HasPrefix(currentArg, "aws_default_region=") {
			awsDefaultRegion = strings.Split(currentArg, "=")[1]
		}
	}

	// check for required environment variables
	checkRequiredEnvVariable("AWS_ACCESS_KEY_ID")
	checkRequiredEnvVariable("AWS_SECRET_ACCESS_KEY")
	checkRequiredEnvVariable("AWS_SESSION_TOKEN")
	checkRequiredEnvVariable("AWS_DEFAULT_REGION")

	if postGithubStatus {
		if targetURL == "" || gitHubURL == "" || gitHubRepo == "" || commitSHA == "" {
			printWithColor(colorRed, "Required GitHub args not provided:", " targetURL:", targetURL, " gitHubURL:",
				gitHubURL, " gitHubRepo:", gitHubRepo, " commitSHA:",
				commitSHA, " You should provide `status=nostatus` or GitHub status report")
			os.Exit(exitCode)
		} else {
			printWithColor(colorGreen, "Running scanner with GitHub status report")
		}
	} else {
		printWithColor(colorYellow, "Running scanner without GitHub status report")
	}
}

func main() {
	printWithColor(colorGreen, "Scanning container image: "+containername+"\n")

	if !strings.Contains(containername, ":") {
		containername += ":latest"
	}

	defer cleanUp()

	awsClient := awspkg.NewAWSSDKClient()
	prismasecret := awspkg.GetSecretFromS3(awsClient, "gd-security-prod-container-scanner-storage", "prisma-secret.json", "us-east-1")

	accesskey, secretid := getPrismaKeys(prismasecret)
	token := getAuthToken(accesskey, secretid)
	twistcli := downloadTwistCli(token.Token)

	saveTwistCli(twistcli)

	resultstring := runTwistCli(token.Token, containername)
	scanResult := formatTwistlockResult(resultstring)

	overrides := getOverridesFromAPI(awsDefaultRegion)

	scanResult.normalize(overrides)

	exitCode = scanResult.reportToCLI(outputFormat)
}

func postGitHubState(ghClient GitHubClient, state string) {
	_, _, err := CreateRepoStatus(ghClient, state)

	if err != nil {
		printWithColor(colorRed, "Reporting "+state+" to GitHub have failed.", err)
	}
}

func cleanUp() {
	if postGithubStatus {
		var ghClient = NewGitHubAPIClient(patToken, targetURL, gitHubURL, gitHubRepo, commitSHA)
		postGitHubState(ghClient, "pending")
		err := recover()
		if err != nil {
			// Panic found, likely an error occurred.
			postGitHubState(ghClient, "error")
			printWithColor(colorRed, err, string(debug.Stack()))
		} else {
			if exitCode == 0 {
				// Successful run, no volnerabilities were found in a container.
				postGitHubState(ghClient, "success")
			} else {
				// Not successful run, one or more volnerabilities were found in a container.
				postGitHubState(ghClient, "failure")
			}
		}

	}
	os.Exit(exitCode)
}
