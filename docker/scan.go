package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/gdcorp-infosec/containerscan-cicd/docker/awspkg"
)

const (
	EXIT_SUCCESS = iota
	EXIT_FAILURE = iota
	EXIT_BAD_ARG = iota
)

const (
	STATUS_NONE   = iota
	STATUS_GITHUB = iota
)

const (
	OUTPUT_TABLE = iota
	OUTPUT_JSON  = iota
)

// ScanResult scan result with compliance and vulnerability findinds
type ScanResult struct {
	ComplianceIssues
	Vulnerabilities
}

type PrismaResult struct {
	Results []struct {
		ScanResult `json:"entityInfo"`
	} `json:"results"`
}

// ComplianceIssues List of compliance findinds
type ComplianceIssues []map[string]interface{}

// Vulnerabilities List of vulnerability findinds
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

	requiredEnvironmentVariables = []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_DEFAULT_REGION",
	}

	containername    string
	patToken         string
	targetURL        string
	gitHubURL        string
	gitHubRepo       string
	commitSHA        string
	awsDefaultRegion string

	statusString     = ""
	outputTypeString = ""

	outputFormat = OUTPUT_JSON
	statusType   = STATUS_GITHUB

	exitCode      = EXIT_FAILURE
	debugMessages []string
)

type token struct {
	Token string
}

func checkRequiredEnvVariableIsSet(name string) {
	if os.Getenv(name) == "" {
		printWithColor(colorYellow, fmt.Sprintf("[WARNING] Required Environment variable %s is not provided. If no alternatives are provided, this may result in error.\n", name))
	}
}

func defineFlags() {
	flag.StringVar(&containername, "container", "", "The name of the container to scan")
	flag.StringVar(&patToken, "githubtoken", "", "Personal Access Token for GitHub")
	flag.StringVar(&outputTypeString, "format", "table", "Scanner Output format; one of: (table|json)")
	flag.StringVar(&statusString, "status", "github", "Kind of status to post; one of (nostatus|github) (if unknown, selects 'github')")
	flag.StringVar(&targetURL, "targeturl", "", "The target URL")
	flag.StringVar(&gitHubURL, "githuburl", "", "The GitHub repository URL, either GHC or GHE")
	flag.StringVar(&gitHubRepo, "repo", "", "Repository to scan")
	flag.StringVar(&commitSHA, "commit", "", "The hash of the commit in the `repo` to check out")
}

func parseAndCheckArgs() bool {
	var checksPass = true

	flag.Parse()

	// this should always be done first to ensure output type is set properly
	switch outputTypeString {
	case "json":
		outputFormat = OUTPUT_JSON
	case "table":
		outputFormat = OUTPUT_TABLE
	default:
		outputFormat = OUTPUT_JSON
		printWithColor(colorYellow, "Warning: unknown output format requested ("+outputTypeString+"), using 'json' instead")
	}

	switch statusString {
	case "nostatus":
		statusType = STATUS_NONE
	case "github":
		statusType = STATUS_GITHUB
	default:
		statusType = STATUS_GITHUB
		printWithColor(colorYellow, "Warning: unknown status type requested ("+outputTypeString+"), using 'github' instead")
	}

	// check for required environment variables
	for _, v := range requiredEnvironmentVariables {
		checkRequiredEnvVariableIsSet(v)
	}

	awsDefaultRegion = os.Getenv("AWS_DEFAULT_REGION")
	if statusType == STATUS_GITHUB {
		if targetURL == "" || gitHubURL == "" || gitHubRepo == "" || commitSHA == "" {
			printWithColor(colorRed, "Required GitHub args not provided:", " targetURL:", targetURL, " gitHubURL:",
				gitHubURL, " gitHubRepo:", gitHubRepo, " commitSHA:",
				commitSHA, " You should provide `status=nostatus` or GitHub status report")
			checksPass = false
		} else {
			printWithColor(colorGreen, "Running scanner with GitHub status report")
		}
	} else {
		printWithColor(colorYellow, "Running scanner without GitHub status report")
	}

	if strings.ContainsAny(containername, "&|;$><`\\!") {
		printWithColor(colorRed, "FATAL: bad container name")
		checksPass = false
	}

	return checksPass
}

func main() {
	defer cleanUp()

	defineFlags()
	if ok := parseAndCheckArgs(); !ok {
		printWithColor(colorRed, "FATAL: some arguments or environment variables were not set")
		exitCode = EXIT_BAD_ARG
		return
	}

	printWithColor(colorGreen, "Scanning container image: "+containername+"\n")

	containername = strings.ReplaceAll(containername, " ", "")

	if !strings.Contains(containername, ":") {
		containername += ":latest"
	}

	awsClient := awspkg.NewAWSSDKClient()
	prismasecret := awspkg.GetSecretFromS3(awsClient, "gd-security-prod-container-scanner-storage", "prisma-secret.json", "us-west-2")

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
		printWithColor(colorRed, fmt.Sprintf("Reporting %s to GitHub have failed : %q", state, err))
	}
}

func cleanUp() {
	var outputErr error
	err := recover()

	if err != nil {
		printWithColor(colorRed, err, string(debug.Stack()))
	}

	if statusType == STATUS_GITHUB {
		var ghClient = NewGitHubAPIClient(patToken, targetURL, gitHubURL, gitHubRepo, commitSHA)
		postGitHubState(ghClient, "pending")
		if err != nil || outputErr != nil {
			// Panic or error found, likely an error occurred.
			postGitHubState(ghClient, "error")
		} else {
			if exitCode == EXIT_SUCCESS {
				// Successful run, no volnerabilities were found in a container.
				postGitHubState(ghClient, "success")
			} else {
				// Not successful run, one or more volnerabilities were found in a container.
				postGitHubState(ghClient, "failure")
			}
		}
	}

	if outputErr = outputResults(exitCode); outputErr != nil {
		prettyPrint(colorRed, outputErr)
	}

	os.Exit(exitCode)
}
