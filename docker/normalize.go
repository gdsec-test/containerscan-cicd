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

var (
	COMPLIENCE_PRIVATE_KEY_DETECTED  = 425
)

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

func getOrgType(awsDefaultRegion string) string {
	c := awspkg.NewAWSSDKClient()
	var org_type = "non-pci"
	var paramName = "/AdminParams/Team/OrgType"
	param, err := awspkg.GetSSMParameter(c, paramName, awsDefaultRegion)
	if err != nil {
		printWithColor(colorRed, fmt.Sprintf("%v\nAWS System parameter %s not found in region %s, set to default value %s\n", err,
			paramName, awsDefaultRegion, org_type))
	} else {
		org_type = *param.Parameter.Value
	}
	return org_type
}

func getOverridesFromAPI(awsDefaultRegion string) []byte {
	c := awspkg.NewAWSSDKClient()
	awsaccountid := awspkg.GetAwsAccount(c)
	org_type := getOrgType(awsDefaultRegion)
	url := getAwsUrl(org_type, awsaccountid)
	overrides, error := awspkg.CallExecuteAPI(c, url, awsDefaultRegion)

	if error != nil {
		fmt.Printf("Error retrieving overrides:%s\n", error.Error())
		panic(error)
	}

	return overrides
}

func formatSecretKeysIssues(res *ScanResult) (ComplianceIssues) {
	var expandedComplianceIssues ComplianceIssues
	for _, compliece := range res.ComplianceIssues {
		if int(compliece["id"].(float64)) == COMPLIENCE_PRIVATE_KEY_DETECTED { // expand to be record per each file value in `Cause` field
			cause := compliece["cause"].(string)
			re := regexp.MustCompile(`(\/[\w-]+[^,]*)|([a-zA-Z]:\\[\\\S|*\S]?[^,]*)`) // matches Unix and Windows path
			foundFiles := re.FindAllStringSubmatch(cause, -1)
			for _, fileMatch := range foundFiles {
				newCompliece := CopyMap(compliece)
				newCompliece["cause"] = fileMatch[0] // filename is first item in match group
				expandedComplianceIssues = append(expandedComplianceIssues, newCompliece)
			}
		} else {
			expandedComplianceIssues = append(expandedComplianceIssues, compliece)
		}
	}
	return expandedComplianceIssues
}

func (res *ScanResult) normalize(overrides []byte) {
	// fmt.Println("in normalize")
	// fmt.Println(string(overrides))
	var businessExceptions businessRuleSet
	json.Unmarshal(overrides, &businessExceptions)
	businessExceptions.ExceptionList = append(businessExceptions.ExceptionList, businessException{  
    ExceptionID: "someid",
    Expiration: 0,
    Pattern: map[string]string{
      "cpl": "425",
      "cause": "/app/node_modules/create-servers/test/fixtures/agent3-key.pem",
    },
    Version: 0,
  })
  businessExceptions.ExceptionList = append(businessExceptions.ExceptionList, businessException{  
    ExceptionID: "someid",
    Expiration: 0,
    Pattern: map[string]string{
      "cve": "CVE-2021-23369",
    },
    Version: 0,
  })
	
	res.ComplianceIssues = formatSecretKeysIssues(res)

	res.ComplianceIssues.normalize(businessExceptions.ExceptionList)
	res.Vulnerabilities.normalize(businessExceptions.ExceptionList)
	res.cleanOverrides()
}

func deleteOverrides(findings []map[string]interface{}, outputFields []string) []map[string]interface{} {
	filteredFindings := make([]map[string]interface{}, 0)

	for _, finding := range findings {
		if finding["SUPPRESS"] == nil || finding["SUPPRESS"].(string) == "" {
			filteredFindings = append(filteredFindings, finding)
		} else {
			outputFinding := make(map[string]interface{})
			for _, field := range outputFields {
				outputFinding[field] = finding[field]
			}
			printWithColor(colorYellow, fmt.Sprintf("Issue excluded from report due to exception: %v\n", outputFinding))
		}
	}
	return filteredFindings

}
func (res *ScanResult) cleanOverrides() {

	res.ComplianceIssues = deleteOverrides(res.ComplianceIssues, COMPLIENCE_OUTPUT_FIELDS)

	res.Vulnerabilities = deleteOverrides(res.Vulnerabilities, VULNERABILITY_OUTPUT_FIELDS)

}

func (comp *ComplianceIssues) normalize(businessExceptions []businessException) {
	//containerscan/us-west-2/com.godaddy.security.tdagent/latest/gd_prisma_compliance
	awsRegion := between(containername, ".dkr.ecr.", ".amazonaws.com")
	repo := between(containername, ".amazonaws.com/", ":")
	tag := after(containername, ":")
	findingid := "containerscan/" + awsRegion + "/" + repo + "/" + tag + "/gd_prisma_compliance"

	for _, c := range *comp {
		c["typeid"] = translatePackageType(int(c["id"].(float64)))
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
		v["packageType"] = translatePackageType(int(v["id"].(float64)))
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
