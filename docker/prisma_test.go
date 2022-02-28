package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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

	prismaSecret = "invalid jason"

	assert.Panics(t, func() { getPrismaKeys(&prismaSecret) }, " Didn't panic reading from invalid prisma secret")

}

func Test_formatTwistlockResult(t *testing.T) {

	result := `=====DATA{
    "results":[
    {
        "entityInfo": {
            "_id": "sha256:random-id",
            "type": "ciImage",
            "hostname": "",
            "scanTime": "2021-02-23T23:06:59.8185397Z",
            "files": null,
            "packageManager": true,
            "id": "sha256:random-id",
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
                },
                {
                    "text": "",
                    "id": 425,
                    "severity": "high",
                    "cvss": 0,
                    "status": "",
                    "cve": "",
                    "cause": "Found: /app/some.key, \n /app/another.crt, \n C:/one/more.pem , /and/too/another.one",
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
            "_id": "random-id",
            "time": "2021-02-23T23:07:00.2349503Z",
            "pass": true,
            "version": "20.12.541"
        }
    }
]
}
`

	formatedResult := formatTwistlockResult(result)
	if len(formatedResult.ComplianceIssues) != 2 {
		t.Error("format error")
	}

}

func Test_formatTwistlockResult_panic(t *testing.T) {

	result := "=====DATAabc{}"
	assert.Panics(t, func() { formatTwistlockResult(result) }, "Didn't panic reading from invalid prisma result")

}

func Test_createAuthTokenRequest(t *testing.T) {

	apiInstance := createAuthTokenRequest("aaa", "bbb")
	if apiInstance == nil {
		t.Error("api creation error")
	}
}

func Test_getAPIResponse_panic(t *testing.T) {

	url := "http://www.randomfakeaaaaa.com"
	payload, _ := json.Marshal(map[string]string{
		"v1": "aaa",
		"v2": "bbb",
	})

	api := API{
		Client:    &http.Client{},
		url:       url,
		authToken: "",
		method:    "POST",
		payload:   payload,
		header:    map[string]string{"content-type": "application/json", "test": "test"},
	}

	assert.Panics(t, func() { api.getAPIResponse() }, "Didn't panic reading from invalid url")

}

func Test_getAPIResponse_OK(t *testing.T) {
	client := &http.Client{}
	api := API{client, "http://www.google.com", "AAAAA", "GET", nil, map[string]string{"content-type": "application/json"}}
	body := api.getAPIResponse()

	if body == nil {
		t.Error("API call error")
	}
	myString := string(body)

	if len(myString) == 0 {
		t.Error("API call error")
	}

}

func Test_translatePackageType(t *testing.T) {
	assert.Equal(t, "OS", translatePackageType(46), "Expected 46 to return OS.")
	assert.Equal(t, "Java", translatePackageType(47), "Expected 47 to return Java.")
	assert.Equal(t, "Gem", translatePackageType(48), "Expected 48 to return Gem.")
	assert.Equal(t, "JavaScript", translatePackageType(49), "Expected 49 to return JavaScript.")
	assert.Equal(t, "Python", translatePackageType(410), "Expected 410 to return Python.")
	assert.Equal(t, "Binary", translatePackageType(411), "Expected 411 to return Binary.")
	assert.Equal(t, "Nuget", translatePackageType(415), "Expected 415 to return Nuget.")
	assert.Equal(t, "-111", translatePackageType(-111), "Expected -111 to return -111.")
}
