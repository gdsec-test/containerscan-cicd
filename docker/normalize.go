package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gdcorp-infosec/containerscan-cicd/docker/awspkg"
)

type businessRuleSet struct {
	ExceptionList []businessException `json:"rule_list"`
}

type businessException struct {
	ExceptionID string            `json:"exception_id"`
	Expiration  int64             `json:"expiration"`
	Pattern     map[string]string `json:"pattern"`
	Version     int               `json:"version"`
}

func (exc *businessException) apply(finding map[string]interface{}) bool {
	//if expired, pass
	if exc.Expiration > 0 {
		if time.Now().UTC().Unix() > exc.Expiration {
			return false
		}
	}

	//if pattern hasn't expired,evaluate rules
	matched := false
	for attr, pattern := range exc.Pattern {
		if len(pattern) == 0 {
			continue
		}
		if finding[strings.ToLower(attr)] == nil {
			return false
		}
		value, ok := finding[strings.ToLower(attr)].(string)

		if ok {
			matchResult, error := regexp.MatchString(pattern, value)
			if error == nil {
				if matchResult {
					// fmt.Printf("Pattern: fieldname %s\tValue: %v  against %s\n", attr, pattern, value)
					matched = true
				} else {
					return false
				}
			} else {
				return false
			}
		} else {
			return false
		}
	}
	//passed all rules
	if matched {
		return true
	}
	return false
}
func getAwsUrl(org_type string, awsaccountid string) string {
	aws_host := ""

	if org_type == "non-pci" {
		aws_host = "api.cirrusscan.gdcorp.tools"
	} else if org_type == "pci" {
		aws_host = "api-p.cirrusscan.gdcorp.tools"
	} else if org_type == "registry" {
		aws_host = "api-r.cirrusscan.gdcorp.tools"
	} else {
		panic("Unrecognized organization type: " + org_type)
	}
	url := fmt.Sprintf("https://%s/v1/exception?account=%s", aws_host, awsaccountid)
	return url
}

func getOverridesFromAPI() []byte {
	c := awspkg.NewAWSSDKClient()
	awsaccountid := awspkg.GetAwsAccount(c)
	org_type := awspkg.GetSSMParameter(c, "/AdminParams/Team/OrgType")
	url := getAwsUrl(org_type, awsaccountid)
	overrides, error := awspkg.CallExecuteAPI(c, url, "us-west-2")

	if error != nil {
		fmt.Printf("Error retrieving overrides:%s\n", error.Error())
		panic(error)
	}

	return overrides
}

func (res *ScanResult) normalize(overrides []byte) {
	// fmt.Println("in normalize")
	// fmt.Println(string(overrides))
	var businessExceptions businessRuleSet
	json.Unmarshal(overrides, &businessExceptions)

	res.ComplianceIssues.normalize(businessExceptions.ExceptionList)
	res.Vulnerabilities.normalize(businessExceptions.ExceptionList)
	res.cleanOverrides()
}

func deleteOverrides(findings []map[string]interface{}) []map[string]interface{} {
	filteredFindings := make([]map[string]interface{}, 0)

	for _, finding := range findings {
		sup := ""
		if finding["SUPPRESS"] != nil {
			sup = finding["SUPPRESS"].(string)
		}
		if sup == "" {
			filteredFindings = append(filteredFindings, finding)
		}
	}
	return filteredFindings

}
func (res *ScanResult) cleanOverrides() {

	res.ComplianceIssues = deleteOverrides(res.ComplianceIssues)

	res.Vulnerabilities = deleteOverrides(res.Vulnerabilities)

}

func (comp *ComplianceIssues) normalize(businessExceptions []businessException) {
	//containerscan/us-west-2/com.godaddy.security.tdagent/latest/gd_prisma_compliance
	awsRegion := between(containername, ".dkr.ecr.", ".amazonaws.com")
	repo := between(containername, ".amazonaws.com/", ":")
	tag := after(containername, ":")
	findingid := "containerscan/" + awsRegion + "/" + repo + "/" + tag + "/gd_prisma_compliance"

	for _, c := range *comp {
		c["cpl"] = strconv.Itoa(int(c["id"].(float64)))
		c["fid"] = findingid
		c["id"] = findingid
		for _, excep := range businessExceptions {
			//if one exception matches, the finding will be suppressed
			if excep.apply(c) {
				c["SUPPRESS"] = "SUPPRESS"
				break
			}
		}
	}
}

func (vuln *Vulnerabilities) normalize(businessExceptions []businessException) {
	// finding id: f"containerscan/{aws_region}/{repository}/{tag}/{r['Package']}",
	//construct finding id
	awsRegion := between(containername, ".dkr.ecr.", ".amazonaws.com")
	repo := between(containername, ".amazonaws.com/", ":")
	tag := after(containername, ":")

	for _, v := range *vuln {
		findingid := "containerscan/" + awsRegion + "/" + repo + "/" + tag + "/"
		pkgname := v["packageName"].(string)

		findingid += pkgname
		v["fid"] = findingid
		v["id"] = findingid

		for _, excep := range businessExceptions {
			//if one exception rule matches, the finding will be suppressed
			if excep.apply(v) {
				v["SUPPRESS"] = "SUPPRESS"
				break
			}
		}
	}
}
