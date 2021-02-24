package main

import (
	// "encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	// "golang.org/x/crypto/blake2b"
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
		fmt.Printf("Pattern: fieldname %s\tValue: %v  against %s\n", attr, pattern, value)
		if ok {
			matchResult, error := regexp.MatchString(pattern, value)
			if error == nil {
				if matchResult {

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

func getOverridesFromAPI() []byte {
	awsaccountid := getAwsAccount()
	org := getSSMParameter("/AdminParams/Team/OrgType")

	appid := "5vhrlp0vbb"
	if org == "pci" {
		appid = "5z4vnar9v4"
	}
	url := fmt.Sprintf("https://%s.execute-api.us-west-2.amazonaws.com/gddeploy/v1/exception?account=%s", appid, awsaccountid)
	overrides, error := callExecuteAPI(url, "us-west-2")

	if error != nil {
		fmt.Printf("Error retrieving overrides:%s\n", error.Error())
		panic(error)
	}
	overrides = []byte(`{
		"rule_list":
	[{"version": 1,	"updated": 1602700832,
	"pattern": {"Fid": "^containerscan/us-east-1/.*/.*/curl",
				"Cve": "^CVE-2020-8285|CVE-2020-36230"
				},
	"expiration": 1618444800	
	"exception_id": "66e68750-7ae3-46bb-b7a4-0c2b3a95d427"
	},{"version": 1,"updated": 1605141042,
	"pattern": {"Fid": "^containerscan/us-east-1/.*/.*/gd_prisma_compliance", 
				"Cpl": "^424"}
	,"expiration": 1618444800,
	"exception_id": "bb86f3e0-63ee-4e19-8fa6-99347f728729"
	}]}`)
	return overrides

}

////COmment out S3 call, use api
/*
func getOverridesFromS3() []byte {
	awsaccountid := getAwsAccount()

	fmt.Printf("aws account: %s", awsaccountid)
	hasher, _ := blake2b.New(20, nil)
	hasher.Write([]byte(awsaccountid))
	hashstring := hex.EncodeToString(hasher.Sum(nil)[:])

	org := getSSMParameter("/AdminParams/Team/OrgType")
	bucket := "gd-audit-prod-cirrus-scan-params"
	if org == "pci" {
		bucket = "gd-audit-prod-cirrus-scan-params-p"
	}

	overrides, error := getS3Object(bucket, "exceptions/"+hashstring)
	fmt.Printf("Retrieved overrides: %s\n", overrides)
	if error != nil {
		fmt.Printf("Error retrieving overrides:%s\n", error.Error())
		panic(error)
	}
	//json from S3 doesn't container rule_list element at root level
	return overrides

}
*/

func (res *ScanResult) normalize(overrides []byte) {
	var businessExceptions businessRuleSet
	json.Unmarshal(overrides, &businessExceptions)

	res.ComplianceIssues.normalize(businessExceptions.ExceptionList)
	res.Vulnerabilities.normalize(businessExceptions.ExceptionList)
	// res.cleanOverrides()
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

		for _, excep := range businessExceptions {
			//if one exception rule matches, the finding will be suppressed
			if excep.apply(v) {
				v["SUPPRESS"] = "SUPPRESS"
				break
			}
		}
	}
}
