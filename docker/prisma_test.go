package main

import (
	"os"
	"testing"
)

func Test_saveTwistCli(t *testing.T) {
	s := "testcontent"
	bs := []byte(s)
	saveTwistCli(bs)
	if _, err := os.Stat("twistcli"); os.IsNotExist(err) {
		t.Error("file twistcli doesn't exist")
	}

}

func Test_getPrismaKeys(t *testing.T) {
	prismaSecret :=
		`{
		"prismaUsername": "username",
		"prismaAccessKeyName": "keyname",
		"prismaAccessKeyId": "accesskeyid",
		"prismaSecretKey": "secretkey",
		"snsTopic": ""
	  }`

	accesskeyid, secretkey := getPrismaKeys(&prismaSecret)
	if accesskeyid != "accesskeyid" {
		t.Error("get accesskeyid error")
	}
	if secretkey != "secretkey" {
		t.Error("get secretkey error")
	}

}

func Test_formatTwistlockResult(t *testing.T) {

	result := `====DATA[
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

	formatedResult := formatTwistlockResult(result)
	if len(formatedResult.ComplianceIssues) == 0 {
		t.Error("format error")

	}
}
