package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func formatTwistlockResult(resultstring string) ScanResult {
	delimiter := "====DATA"
	res := resultstring[strings.Index(resultstring, delimiter)+len(delimiter):]

	s := []struct {
		EntityInfo ScanResult
	}{}

	if err := json.Unmarshal([]byte(res), &s); err != nil {
		printWithColor(colorRed, "Error : Unable to unmarshal twistlock result", err)
		os.Exit(1)
	}

	return s[0].EntityInfo
}

func getAuthToken(username string, password string) token {

	url := prismaConsoleURL + "/api/v1/authenticate"

	postBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, bytes.NewReader(postBody))
	req.Header.Add("content-type", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		println(err.Error()) // handle error
	}
	defer resp.Body.Close()

	// r = requests.post(
	// url, headers={"content-type": "application/json"}, data=respo
	// token = r.json()["token"]
	body, _ := ioutil.ReadAll(resp.Body)
	tokenjson := string(body)
	var token token
	json.Unmarshal([]byte(tokenjson), &token)
	return token
}

func getAPIResponse(url string, authToken string) []byte {
	var body []byte
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 2 * time.Minute

	client := &http.Client{}
	var resp *http.Response
	var err error
	var apierror error
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+authToken)

	err = backoff.Retry(func() error {
		resp, apierror = client.Do(req)
		if apierror != nil {
			return apierror
		}
		defer resp.Body.Close()
		apibody, readerror := ioutil.ReadAll(resp.Body)
		if apierror != nil {
			return readerror
		}
		body = apibody
		return nil
	}, bo)

	if err != nil {
		printWithColor(colorRed, "Error : Failed to call API", err)
		os.Exit(1)
	}
	return body
}

func downloadTwistCli(token string) {
	twistcli := getAPIResponse(prismaConsoleURL+"/api/v1/util/twistcli", token)

	err := ioutil.WriteFile("twistcli", twistcli, 0755)
	if err != nil {
		printWithColor(colorRed, "Error : Failed to download cli", err)
		os.Exit(1)
	}
}

func runTwistCli(token string, container string) string {
	cmd := exec.Command("/bin/sh", "-c", "./twistcli images scan --details --address "+prismaConsoleURL+" --token "+token+" --ci "+container)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		printWithColor(colorRed, "Error : Unexpected error while executing twistlock cli", err, stderr.String())
		os.Exit(1)
	}

	return out.String()
}

func getPrismaSecret() (string, string) {
	prismasecret := getSecret(prismaSecretName, "us-east-1")

	var p map[string]interface{}
	err := json.Unmarshal([]byte(*prismasecret), &p)
	if err != nil {
		panic(err)
	}

	prismaAccessKeyID := p["prismaAccessKeyId"].(string)
	prismaSecretKey := p["prismaSecretKey"].(string)

	return prismaAccessKeyID, prismaSecretKey
}
