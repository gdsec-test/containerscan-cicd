package main

import (
	"testing"
)

func Test_Normalize(t *testing.T) {

	overrides := []byte(`{
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

	scanresult := `====DATA[
    {
        "entityInfo": {
            "_id": "sha256:8c1c64b494fa20541be87a87d23c67c17684501c62e0684cd663c138c38cba3f",
            "type": "ciImage",
            "hostname": "",
            "scanTime": "2021-02-23T23:06:59.8185397Z",
            "files": null,
            "packageManager": true,
            "id": "sha256:8c1c64b494fa20541be87a87d23c67c17684501c62e0684cd663c138c38cba3f",
            "complianceIssues": [
                {
                    "text": "",
                    "id": 41,
                    "severity": "high",
                    "cvss": 0,
                    "status": "",
                    "cve": "",
                    "cause": "",
                    "description": "It is a good practice to run the container as a non-root user, if possible. Though user\nnamespace mapping is now available, if a user is already defined in the container image, the\ncontainer is run as that user by default and specific user namespace remapping is not\nrequired",
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
                    "description": "musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. In some cases, use of this library could introduce out-of-bounds writes that are not present in an application\\'s source code.",
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
            "_id": "000000000000000000000000",
            "time": "2021-02-23T23:07:00.2349503Z",
            "pass": true,
            "version": "20.12.541"
        }
    }
]
	`

	formatedResult := formatTwistlockResult(scanresult)

	formatedResult.normalize(overrides)
	if len(formatedResult.ComplianceIssues) == 0 {
		t.Error("normalize failed")
	}

}
