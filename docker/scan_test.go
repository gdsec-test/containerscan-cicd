package main

import (
	"os"
	"testing"
)

func setRequiredEnvVarsForTesting() {
	for _, v := range requiredEnvironmentVariables {
		os.Setenv(v, "fake_"+v)
	}
}

func Test_checkRequiredEnvVariableIsSet(t *testing.T) {
	for _, v := range requiredEnvironmentVariables {
		os.Unsetenv(v)
		isSet := checkRequiredEnvVariableIsSet(v)
		if isSet {
			t.Error("Environment variable " + v + " got set somehow")
		}
	}

	setRequiredEnvVarsForTesting()
	for _, v := range requiredEnvironmentVariables {
		isSet := checkRequiredEnvVariableIsSet(v)
		if !isSet {
			t.Error("Environment variable got set somehow")
		}
	}
}

func Test_parseAndCheckArgs(t *testing.T) {
	setRequiredEnvVarsForTesting()
	os.Args = []string{os.Args[0]}

	defineFlags()
	result := parseAndCheckArgs()
	if result == true {
		t.Error("Arguments validation should not have succeeded")
	}

	os.Args = []string{os.Args[0], "--status=nostatus", "--format=anotherfakeoption"}
	result = parseAndCheckArgs()
	if result == false {
		t.Error("Arguments validation should not have failed")
	}

	os.Args = []string{os.Args[0],
		"--status=github",
		"--commit=01234567", // fake commit
		"--githuburl=https://github.secureserver.net",
		"--targeturl=https://github.com/gdcorp-infosec/containerscan-cicd",
		"--repo=nonexistentrepositoryowner/nonexistentrepositoryrepository",
		"--format=table",
	}
	result = parseAndCheckArgs()
	if result == false {
		t.Error("Arguments validation should not have succeeded")
	}
}
