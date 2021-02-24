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
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	api := API{
		Client:    &http.Client{},
		url:       url,
		authToken: "",
		method:    "POST",
		payload:   payload,
	}
	tokenresult := api.getAPIResponse()
	var token token
	json.Unmarshal(tokenresult, &token)
	return token
}

type API struct {
	Client    *http.Client
	url       string
	authToken string
	method    string
	payload   []byte
}

func (api *API) getAPIResponse() []byte {
	var body []byte
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 2 * time.Minute

	client := api.Client
	var resp *http.Response
	var err error
	var apierror error
	req, _ := http.NewRequest(api.method, api.url, bytes.NewReader(api.payload))
	if api.authToken != "" {
		req.Header.Add("Authorization", "Bearer "+api.authToken)
	} else {
		req.Header.Add("content-type", "application/json")
	}
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

func downloadTwistCli(token string) []byte {
	api := API{
		Client:    &http.Client{},
		url:       prismaConsoleURL + "/api/v1/util/twistcli",
		authToken: token,
		method:    "GET",
		payload:   nil,
	}
	twistcli := api.getAPIResponse()
	return twistcli

}
func saveTwistCli(twistcli []byte) {
	err := ioutil.WriteFile("twistcli", twistcli, 0755)
	if err != nil {
		printWithColor(colorRed, "Error : Failed to download cli", err)
		os.Exit(1)
	}
}

func runTwistCli(token string, container string) string {
	cmd := exec.Command("/bin/sh", "-c", "./twistcli images scan --details --address "+prismaConsoleURL+" --token "+token+" --ci "+container)
	return runOSCommandWithOutput(cmd)
}

func runOSCommandWithOutput(cmd *exec.Cmd) string {

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		printWithColor(colorRed, "Error : Unexpected error while executing command", err, stderr.String())
		os.Exit(1)
	}

	return out.String()
}

func getPrismaKeys(prismasecret *string) (string, string) {

	var p map[string]interface{}
	err := json.Unmarshal([]byte(*prismasecret), &p)
	if err != nil {
		panic(err)
	}

	prismaAccessKeyID := p["prismaAccessKeyId"].(string)
	prismaSecretKey := p["prismaSecretKey"].(string)

	return prismaAccessKeyID, prismaSecretKey
}
