package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var scanresult = `=====DATA{
  "results":[{
    "entityInfo": {
        "_id": "sha256:randomid",
        "type": "ciImage",
        "hostname": "",
        "scanTime": "2021-02-23T23:06:59.8185397Z",
        "files": null,
        "packageManager": true,
        "id": "sha256:randomid",
        "complianceIssues": [
            {
                "text": "",
                "id": 41,
                "severity": "high",
                "cvss": 0,
                "status": "",
                "cve": "",
                "cause": "",
                "description": "It is a good practice to run the container as a non-root user, if possible.",
                "title": "(CIS_Docker_CE_v1.1.0 - 4.1) Image should be created with a non-root user",
                "vecStr": "",
                "exploit": "",
                "riskFactors": null,
                "link": "",
                "type": "image",
                "packageName": "",
                "packageVersion": "",
                "layerTime": 0,
                "templates": null,
                "twistlock": false,
                "cri": false,
                "published": 0,
                "fixDate": 0,
                "discovered": "0001-01-01T00:00:00Z"
            },
            {
              "text": "",
              "id": 425,
              "severity": "high",
              "cvss": 0,
              "status": "",
              "cve": "",
              "cause": "Found: /app/some.key, \n /app/another.crt",
              "title": "Private keys stored in image",
              "type": "image",
              "packageName": "",
              "packageVersion": "",
              "layerTime": 0,
              "templates": null,
              "twistlock": false,
              "cri": false,
              "published": 0,
              "fixDate": 0,
              "discovered": "0001-01-01T00:00:00Z"
          }
        ],
        "allCompliance": {},
        "vulnerabilities": [
            {
                "text": "",
                "id": 46,
                "severity": "critical",
                "cvss": 9.8,
                "status": "fixed in 1.1.20-r5",
                "cve": "CVE-2019-14697",
                "cause": "",
                "description": "musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. ",
                "title": "",
                "vecStr": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "exploit": "",
                "riskFactors": {
                    "Attack complexity: low": {},
                    "Attack vector: network": {},
                    "Critical severity": {},
                    "Has fix": {}
                },
                "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-14697",
                "type": "image",
                "packageName": "musl",
                "packageVersion": "1.1.20-r3",
                "layerTime": 1552000638,
                "templates": null,
                "twistlock": false,
                "cri": false,
                "published": 1565108100,
                "fixDate": 1565108100,
                "applicableRules": [
                    "\u003c1.1.20-r5"
                ],
                "discovered": "2021-02-23T23:06:57.6291032Z",
                "binaryPkgs": [
                    "musl-utils",
                    "musl"
                ]
            }
        ],
        "_id": "random-id",
        "time": "2021-02-23T23:07:00.2349503Z",
        "pass": true,
        "version": "20.12.541"
    }
  }
 ]
}
`

func Test_Normalize_withoutMatch(t *testing.T) {
	containername = "11111111111.dkr.ecr.us-west-2.amazonaws.com/some-image:latest"

	formatedResult := formatTwistlockResult(scanresult)

	overrides := []byte(`{
        "rule_list": [
          {
            "version": 1,
            "updated": 1602700832,
            "pattern": {
              "Fid": "^containerscan/us-west-2/.*/.*/infected-package",
              "Cve": "^CVE-2019-14697|CVE-2020-36230"
            },
            "expiration": 1845774345,
            "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
            "exception_id": "random-id",
            "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
          },
          {
            "version": 1,
            "updated": 1605141042,
            "pattern": {
              "Fid": "^containerscan/us-west-2/.*/.*/gd_prisma_compliance",
              "Cpl": "^99999999"
            },
            "expiration": 1845774345,
            "comment": "Scans on GD-SOME-ACCOUNT Accounts",
            "exception_id": "random-id",
            "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
          }
        ]
      }`)

	formatedResult.normalize(overrides)
	if len(formatedResult.ComplianceIssues) == 0 {
		t.Error("normalize failed")
	}
}

func Test_Normalize_match_allrules_but_one(t *testing.T) {

	formatedResult := formatTwistlockResult(scanresult)

	overrides := []byte(`{
        "rule_list": [
          {
            "version": 1,
            "updated": 1602700832,
            "pattern": {
              "Fid": "^containerscan/us-west-2/.*/.*/musl",
              "Cve": "^CVE-2019-14697|CVE-2020-36230"
            },
            "expiration": 1845774345,
            "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
            "exception_id": "random-id",
            "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
          },
          {
            "version": 1,
            "updated": 1605141042,
            "pattern": {
              "Fid": "^containerscan/us-west-2/.*/.*/gd_prisma_compliance",
              "Cpl": "^41"
            },
            "expiration": 1845774345,
            "comment": "Scans on GD-SOME-ACCOUNT Accounts",
            "exception_id": "random-id",
            "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
          },
          {
            "version": 1,
            "updated": 1605141042,
            "pattern": {
              "Fid": "^containerscan/us-west-2/.*/.*/gd_prisma_compliance",
              "cause": "/app/another.crt",
              "Cpl": "^425"
            },
            "expiration": 1845774345,
            "comment": "Scans on GD-SOME-ACCOUNT Accounts",
            "exception_id": "random-id",
            "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
          },
          {
            "version": 1,
            "updated": 1605141042,
            "pattern": {
              "Fid": "^containerscan/us-west-2/.*/.*/gd_prisma_compliance",
              "cause": "C:/one/more.pem",
              "Cpl": "^425"
            },
            "expiration": 1845774345,
            "comment": "Scans on GD-SOME-ACCOUNT Accounts",
            "exception_id": "random-id",
            "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
          }
        ]
      }`)

	formatedResult.normalize(overrides)
	if len(formatedResult.ComplianceIssues) != 1 {
		fmt.Printf("%v", formatedResult.ComplianceIssues)
		t.Error("normalize failed. Complience exceptions were not properly filtered out")
	}
}

func Test_apply_partial_match(t *testing.T) {
	overrides := []byte(`{
    "rule_list": [
      {
        "version": 1,
        "updated": 1602700832,
        "pattern": {
          "Fid": "^containerscan/us-west-2/.*/.*/musl",
          "Cve": "^CVE-123"
        },
        "expiration": 1845774345,
        "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
        "exception_id": "random-id",
        "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
      }
      ]
  }`)

	formatedResult := formatTwistlockResult(scanresult)

	formatedResult.normalize(overrides)
	if len(formatedResult.Vulnerabilities) != 1 {
		t.Error("Apply failed")
	}

}

func Test_apply_nomatch_2(t *testing.T) {

	overrides := []byte(`{
    "rule_list": [
      {
        "version": 1,
        "updated": 1602700832,
        "pattern": {
          "Fid": "^aaa/us-west-2/.*/.*/aaa",
          "Cve": "^CVE-123"
        },
        "expiration": 1845774345,
        "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
        "exception_id": "random-id",
        "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
      }
      ]
  }`)

	formatedResult := formatTwistlockResult(scanresult)

	formatedResult.normalize(overrides)
	if len(formatedResult.Vulnerabilities) != 1 {
		t.Error("Apply failed")
	}
}

func Test_apply_no_overrides(t *testing.T) {

	overrides := []byte(`{
    "rule_list": [
      ]
  }`)

	formatedResult := formatTwistlockResult(scanresult)

	formatedResult.normalize(overrides)
	if len(formatedResult.Vulnerabilities) != 1 {
		t.Error("Apply failed")
	}
}

func Test_apply_expired_rule(t *testing.T) {
	overrides := []byte(`{
    "rule_list": [
      {
        "version": 1,
        "updated": 1602700832,
        "pattern": {"Fid": "^containerscan/us-west-2/.*/.*/musl",
          "Cve": "^CVE-2019-14697|CVE-2020-36230" },
        "expiration": 1145774345,
        "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
        "exception_id": "random-id",
        "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
      }
      ]
  }`)

	formatedResult := formatTwistlockResult(scanresult)
	formatedResult.normalize(overrides)
	if len(formatedResult.Vulnerabilities) != 1 {
		t.Error("Apply failed")
	}

}

func Test_apply_Zero_length_pattern(t *testing.T) {
	overrides := []byte(`{
    "rule_list": [
      {
        "version": 1,
        "updated": 1602700832,
        "pattern": {"aaa": "","bbb": ""},
        "expiration": 1945774345,
        "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
        "exception_id": "random-id",
        "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
      }
      ]
  }`)
	formatedResult := formatTwistlockResult(scanresult)
	formatedResult.normalize(overrides)
	if len(formatedResult.Vulnerabilities) != 1 {
		t.Error("Apply failed")
	}
}

func Test_apply_no_matching_attribute(t *testing.T) {
	overrides := []byte(`{
    "rule_list": [
      {
        "version": 1,
        "updated": 1602700832,
        "pattern": {"aaa": "containerscan/"},
        "expiration": 1945774345,
        "comment": "Scans on GD-SOME-ACCOUNT Accounts | Standard Ports",
        "exception_id": "random-id",
        "author": "arn:aws:sts::11111111111:assumed-role/GD-Admin/test@test.godaddy.com"
      }
      ]
  }`)
	formatedResult := formatTwistlockResult(scanresult)
	formatedResult.normalize(overrides)
	if len(formatedResult.Vulnerabilities) != 1 {
		t.Error("Apply failed")
	}
}

func Test_getAwsUrl_nonpci(t *testing.T) {
	org_type := "non-pci"
	awsaccountid := "123456"
	result := getAwsUrl(org_type, awsaccountid)
	if result != "https://api.cirrusscan.gdcorp.tools/v1/exception?account=123456" {
		t.Error("Get aws url failed")
	}
}

func Test_getAwsUrl_pci(t *testing.T) {
	org_type := "pci"
	awsaccountid := "123456"
	result := getAwsUrl(org_type, awsaccountid)
	if result != "https://api-p.cirrusscan.gdcorp.tools/v1/exception?account=123456" {
		t.Error("Get aws url failed")
	}
}
func Test_getAwsUrl_registry(t *testing.T) {
	org_type := "registry"
	awsaccountid := "123456"
	result := getAwsUrl(org_type, awsaccountid)
	if result != "https://api-r.cirrusscan.gdcorp.tools/v1/exception?account=123456" {
		t.Error("Get aws url failed")
	}
}

func Test_getAwsUrl_panic(t *testing.T) {
	org_type := "random"
	awsaccountid := "123456"

	assert.Panics(t, func() { getAwsUrl(org_type, awsaccountid) }, "Didn't panic with bad org_type")
}
