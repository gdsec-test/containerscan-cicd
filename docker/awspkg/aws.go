package awspkg

import (
	"io/ioutil"
	"github.com/aws/aws-sdk-go/service/ssm"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
)

func GetSecretFromS3(c AWSClient, bucketName string, objectName string, region string) *string {
	result, err := c.GetS3Object(bucketName, objectName, region)

	if err != nil {
		panic(err)
	}
	resultString := string(result)
	return &resultString
}

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

func GetSSMParameter(c AWSClient, name string, region string) (*ssm.GetParameterOutput, error) {
	param, err := c.GetParameter(name, region)
	return param, err
}

func GetAwsAccount(c AWSClient) string {
	result, _ := c.GetCallerIdentity()
	return *result.Account
}
