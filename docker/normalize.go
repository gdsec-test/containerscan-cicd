package main

import "fmt"

func (res *ScanResult) normalize() {
	/////TODO: get org and set different app id

	org := getSSMParameter("/AdminParams/Team/OrgType")

	appid := "5vhrlp0vbb"
	if org == "pci" {
		appid = "5z4vnar9v4"
	}
	url := "https://" + appid + ".execute-api.us-west-2.amazonaws.com/gddeploy/v1/exception"
	overrides, error := callExecuteAPI(url, "us-west-2")
	fmt.Printf("overrides: %s\n", overrides)
	if error != nil {
		fmt.Printf("Error retrieving overrides:%s\n", error.Error())
		panic(error)
	}

	res.ComplianceIssues.normalize()
	res.Vulnerabilities.normalize()

}

func (comp *ComplianceIssues) normalize() {
	printWithColor(colorBlue, "ComplianceIssues Normalization Not Implemented.")
}

func (vuln *Vulnerabilities) normalize() {
	printWithColor(colorBlue, "Vulnerabilities Normalization Not Implemented.")
}
