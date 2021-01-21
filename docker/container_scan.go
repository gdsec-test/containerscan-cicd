package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func csvReader(file string) *csv.Reader {
	// 1. Open the file
	recordFile, err := os.Open(file)
	if err != nil {
		fmt.Println("An error encountered ::", err)
	}
	// 2. Initialize the reader
	reader := csv.NewReader(recordFile)
	return reader
	// 3. Read all the records
	// records, _ := reader.ReadAll()
	// // 4. Iterate through the records as you wish
	// fmt.Println(records)
}

func get_access_keys(key_file string) (string, string) {

	absPath, _ := filepath.Abs(key_file)
	println(absPath)
	reader := csvReader(absPath)
	result := make(map[string]string)

	for {

		row, err := reader.Read()
		// fmt.Printf("%s\n", row)
		if err == io.EOF {
			break
		}

		// for value := range row {
		key := strings.TrimSpace(row[0])
		// if _, ok := result[key]; ok {
		// continue
		// }

		result[key] = strings.TrimSpace(row[1])

		// fmt.Printf(row[0], "::", row[1])
		// }

	}
	// fmt.Print(result)
	// fmt.Printf(result["Secret Key"])
	return result["Access Key ID"], result["Secret Key"]

}

func getAuthToken(CONSOLEURI string, username string, password string) Token {

	url := CONSOLEURI + "/api/v1/authenticate"

	postBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, bytes.NewReader(postBody))
	req.Header.Add("content-type", "application/json")
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	// r = requests.post(
	// url, headers={"content-type": "application/json"}, data=respo
	// token = r.json()["token"]
	body, _ := ioutil.ReadAll(resp.Body)
	tokenjson := string(body)
	var token Token
	json.Unmarshal([]byte(tokenjson), &token)
	return token
}

type Token struct {
	Token string
}

func get_response(url string, auth_token string) []byte {

	// b := BackOff.NewExponentialBackOff()
	// b.MaxElapsedTime = 3 * time.Minute

	// err = BackOff.Retry(doSomething(), b)
	// if err != nil {
	// log.Fatalf("error after retrying: %v", err)
	// }

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+auth_token)
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return body
}

func downloadCli(CONSOLEURI string, token string) {
	twistcli := get_response(CONSOLEURI+"/api/v1/util/twistcli", token)

	err := ioutil.WriteFile("twistcli", twistcli, 0755)
	if err != nil {
		println(err.Error()) // handle error
	}
}

func runScan2(url string, token string, container string) {
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

func runScan(url string, token string, container string) {

	// cmd := exec.Command("/bin/sh", "-c", "sudo find ...")

	// out, err := exec.Command("/bin/sh", "-c", "./twistcli images scan --details --address "+url+"  -u "+accesskey+" -p "+secretkey+" --ci containerscan:latest").Output()
	out, err := exec.Command("/bin/sh", "-c", "./twistcli images scan --details --address "+url+"  --token "+token+" --ci "+container).Output()

	if err != nil {
		println("error execute cli")
		println(err.Error())
	} else {
		stringout := string(out)
		// stringout = stringout[:strings.Index(stringout, "=====DATA[{")]
		println(stringout)
	}

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

	downloadCli(CONSOLEURI, token.Token)

	runScan2(CONSOLEURI, token.Token, container)
	// none-zero status, fails step
	// os.Exit(3)
}
