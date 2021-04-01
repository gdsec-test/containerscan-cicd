package awspkg

import (
	"io/ioutil"
)

// GetSecret retrieve aws secretmanager secret
func GetSecret(c AWSClient, secretname string, region string) *string {
	result, err := c.GetSecretValue(secretname, region)

	if err != nil {
		panic(err)
	}

	return result.SecretString
}

// Get V4 Signed http Executable
func CallExecuteAPI(c AWSClient, url string, region string) ([]byte, error) {
	resp, err := c.ExecuteRequest(url, region)

	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	return b, err
}

func GetSSMParameter(c AWSClient, name string) string {
	param, err := c.GetParameter(name)

	if err != nil {
		panic(err)
	}

	return *param.Parameter.Value
}

func GetAwsAccount(c AWSClient) string {
	result, _ := c.GetCallerIdentity()
	return *result.Account
}
