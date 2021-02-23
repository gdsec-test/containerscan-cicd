package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
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
		// fmt.Println("Pattern: fieldname %s\tValue: %v\n against %s", attr, pattern, value)

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

	org := getSSMParameter("/AdminParams/Team/OrgType")

	appid := "5vhrlp0vbb"
	if org == "pci" {
		appid = "5z4vnar9v4"
	}
	url := "https://" + appid + ".execute-api.us-west-2.amazonaws.com/gddeploy/v1/exception"
	overrides, error := callExecuteAPI(url, "us-west-2")

	fmt.Printf("Retrieved overrides: %s\n", overrides)
	if error != nil {
		fmt.Printf("Error retrieving overrides:%s\n", error.Error())
		panic(error)
	}
	overrides = []byte(`{
		"rule_list":
	[{"version": 1,	"updated": 1602700832,
	"pattern": {"Id": "^containerscan/us-east-1/.*/.*/openssl",
				"Cve": "^CVE-2020-8285|CVE-2020-36230"
				},
	"expiration": 1618444800,"comment": "Scans on GD-AWS-USA-CPO-OXManaged Accounts | Standard Ports",
	"exception_id": "66e68750-7ae3-46bb-b7a4-0c2b3a95d427",
	"author": "arn:aws:sts::672751022979:assumed-role/GD-AWS-Global-Audit-Admin/rbailey@godaddy.com"
	},{"version": 1,"updated": 1605141042,
	"pattern": {"Id": "^containerscan/us-east-1/sampleimagename/latst/gd_compliance_finding", 
				"Cpl": "^41"}
	,"expiration": 1618444800,
	"comment": "Scans on GD-AWS-USA-CPO-OXManaged Accounts | Non-Golden AMIs",	"exception_id": "bb86f3e0-63ee-4e19-8fa6-99347f728729",
	"author": "arn:aws:sts::672751022979:assumed-role/GD-AWS-Global-Audit-Admin/smimani@godaddy.com"
	}]}`)
	return overrides

}

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
	overrides = []byte(`
	[{"version": 1,	"updated": 1602700832,
	"pattern": {"Id": "^containerscan/us-east-1/.*/.*/openssl",
				"Cve": "^CVE-2020-8285|CVE-2020-36230"
				},
	"expiration": 1618444800,"comment": "Scans on GD-AWS-USA-CPO-OXManaged Accounts | Standard Ports",
	"exception_id": "66e68750-7ae3-46bb-b7a4-0c2b3a95d427",
	"author": "arn:aws:sts::672751022979:assumed-role/GD-AWS-Global-Audit-Admin/rbailey@godaddy.com"
	},{"version": 1,"updated": 1605141042,
	"pattern": {"Id": "^containerscan/us-east-1/sampleimagename/latst/gd_compliance_finding", 
				"Cpl": "^41"}
	,"expiration": 1618444800,
	"comment": "Scans on GD-AWS-USA-CPO-OXManaged Accounts | Non-Golden AMIs",	"exception_id": "bb86f3e0-63ee-4e19-8fa6-99347f728729",
	"author": "arn:aws:sts::672751022979:assumed-role/GD-AWS-Global-Audit-Admin/smimani@godaddy.com"
	}]`)

	return overrides

}

func (res *ScanResult) normalize() {
	overrides := getOverridesFromAPI()
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
	// containerscan/us-west-2/containerscan/latest/krb5
	// 226955763576.dkr.ecr.us-east-1.amazonaws.com/security-fluentd-aggregator-dev-private:latest

	//construct finding id
	awsRegion := between(containername, ".dkr.ecr.", ".amazonaws.com")
	repo := between(containername, ".amazonaws.com/", ":")
	tag := after(containername, ":")

	for _, v := range *vuln {
		findingid := "containerscan/" + awsRegion + "/" + repo + "/" + tag + "/"
		pkgname := v["packageName"].(string)

		findingid += pkgname
		v["id"] = findingid

		for _, excep := range businessExceptions {
			//if one exception matches, the finding will be suppressed
			isMatched := excep.apply(v)
			fmt.Printf("finding id: %s - %s\n", strconv.FormatBool(isMatched), findingid)
			if isMatched {
				v["SUPPRESS"] = "SUPPRESS"
				break
			}
		}
	}
}
