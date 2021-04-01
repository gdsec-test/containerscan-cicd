package awspkg

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
)

type MockAWSClient struct {
	shouldError bool
}

func (c *MockAWSClient) newSession() *session.Session {
	return new(session.Session)
}

func (c *MockAWSClient) GetCallerIdentity() (*sts.GetCallerIdentityOutput, error) {
	var err error
	str := "test-account"

	if c.shouldError {
		err = errors.New("GetCallerIdentity ERRORED")
	}

	return &sts.GetCallerIdentityOutput{Account: &str}, err
}

func (c *MockAWSClient) GetParameter(name string) (*ssm.GetParameterOutput, error) {
	var err error
	str := "test-value"

	if c.shouldError {
		err = errors.New("GetParameter ERRORED")
	}

	return &ssm.GetParameterOutput{Parameter: &ssm.Parameter{Value: &str}}, err
}

func (c *MockAWSClient) ExecuteRequest(url string, region string) (*http.Response, error) {
	var err error

	if c.shouldError {
		err = errors.New("ExecuteRequest ERRORED")
	}

	readCloser := ioutil.NopCloser(bytes.NewReader([]byte("test")))

	return &http.Response{Body: readCloser}, err
}

func (c *MockAWSClient) GetSecretValue(region string, secretName string) (*secretsmanager.GetSecretValueOutput, error) {
	var err error
	str := "test-secret"

	if c.shouldError {
		err = errors.New("GetSecretValue ERRORED")
	}

	return &secretsmanager.GetSecretValueOutput{SecretString: &str}, err
}

func NewMockAWSClient(shouldError bool) AWSClient {
	c := &MockAWSClient{
		shouldError,
	}
	return c
}

func assertPanic(t *testing.T) {
	if recover() == nil {
		t.Error("The code did not panic")
	}
}

func TestGetSecret_HappyPath(t *testing.T) {
	c := NewMockAWSClient(false)
	secretName := "test-secret"
	region := "us-east-1"

	GetSecret(c, secretName, region)
}

func TestGetSecret_ErrorPath(t *testing.T) {
	defer assertPanic(t)
	c := NewMockAWSClient(true)
	secretName := "test-secret"
	region := "us-east-1"

	GetSecret(c, secretName, region)
}

func TestCallExecuteAPI_HappyPath(t *testing.T) {
	c := NewMockAWSClient(false)

	CallExecuteAPI(c, "test-url", "test-region")
}

func TestCallExecuteAPI_ErrorPath(t *testing.T) {
	c := NewMockAWSClient(true)

	res, err := CallExecuteAPI(c, "test-url", "test-region")

	if res != nil || err == nil {
		t.Error("CallExecuteAPI should return error with no result on ExecuteRequest failure.")
	}
}

func TestGetSSMParameter_HappyPath(t *testing.T) {
	c := NewMockAWSClient(false)
	name := "test-value"

	GetSSMParameter(c, name)
}

func TestGetSSMParameter_ErrorPath(t *testing.T) {
	defer assertPanic(t)
	c := NewMockAWSClient(true)
	name := "test-value"

	GetSSMParameter(c, name)
}

func TestGetAwsAccount(t *testing.T) {
	c := NewMockAWSClient(false)
	GetAwsAccount(c)
}
