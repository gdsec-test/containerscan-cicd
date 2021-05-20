package main

import (
	"bytes"
	"encoding/json"
	"github.com/cenkalti/backoff/v4"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type API struct {
	Client    *http.Client
	url       string
	authToken string
	method    string
	payload   []byte
	header    map[string]string
}

func formatTwistlockResult(resultstring string) ScanResult {
	delimiter := "====DATA"
	res := resultstring[strings.Index(resultstring, delimiter)+len(delimiter):]

	s := []struct {
		EntityInfo ScanResult
	}{}

	if err := json.Unmarshal([]byte(res), &s); err != nil {
		printWithColor(colorRed, "Error : Unable to unmarshal twistlock result", err)
		panic(err)
	}

	return s[0].EntityInfo
}

func createAuthTokenRequest(username string, password string) *API {
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
		header:    map[string]string{"content-type": "application/json"},
	}
	return &api

}

func getAuthToken(username string, password string) token {
	api := createAuthTokenRequest(username, password)
	tokenresult := api.getAPIResponse()
	var token token
	json.Unmarshal(tokenresult, &token)
	return token
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
	if api.header != nil {
		for k, v := range api.header {
			req.Header.Add(k, v)
		}

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
		panic(err)
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
		header:    map[string]string{"Authorization": "Bearer " + token},
	}
	twistcli := api.getAPIResponse()
	return twistcli

}
func saveTwistCli(twistcli []byte) {
	err := ioutil.WriteFile("twistcli", twistcli, 0755)
	if err != nil {
		printWithColor(colorRed, "Error : Failed to download cli", err)
		panic(err)
	}
}

func runTwistCli(token string, container string) string {
	commandline := "./twistcli images scan --details --address " + prismaConsoleURL + " --token " + token + " --ci " + container
	cmd := exec.Command("/bin/sh", "-c", commandline)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		printWithColor(colorRed, "Error : Unexpected error while executing command", err, stderr.String())
		panic(err)
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
