package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
)

func getAuthToken(CONSOLEURI string, username string, password string) token {

	url := CONSOLEURI + "/api/v1/authenticate"

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

type token struct {
	Token string
}

func getAPIResponse(url string, authToken string) []byte {

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+authToken)
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error()) // handle error
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return body
}

func downloadTwistCli(CONSOLEURI string, token string) {
	twistcli := getAPIResponse(CONSOLEURI+"/api/v1/util/twistcli", token)

	err := ioutil.WriteFile("twistcli", twistcli, 0755)
	if err != nil {
		println(err.Error()) // handle error
	}
}

func runTwistCli(url string, token string, container string) {
	colorRed := "\033[31m"
	cmd := exec.Command("/bin/sh", "-c", "./twistcli images scan --address "+url+"  --token "+token+" --ci "+container)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(string(colorRed), fmt.Sprint(err)+": "+stderr.String())
		return
	}
	fmt.Println("Result: " + out.String())
}

func main() {
	arg := os.Args
	// colorReset := "\033[0m"

	//colorRed := "\033[31m"
	colorGreen := "\033[32m"
	// colorYellow := "\033[33m"
	// colorBlue := "\033[34m"
	// colorPurple := "\033[35m"
	// colorCyan := "\033[36m"
	// colorWhite := "\033[37m"

	fmt.Println(string(colorGreen), "Run GOLANG")

	CONSOLEURI := "https://us-east1.cloud.twistlock.com/us-2-158254964"
	accesskey := arg[1]
	secretid := arg[2]
	container := arg[3]
	token := getAuthToken(CONSOLEURI, accesskey, secretid)

	downloadTwistCli(CONSOLEURI, token.Token)

	runTwistCli(CONSOLEURI, token.Token, container)
	// none-zero status, fails step
	// os.Exit(3)
}
