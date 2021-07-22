package awspkg

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
)

func TestNewAWSSDKClient(t *testing.T) {
	c := NewAWSSDKClient()

	if reflect.ValueOf(c).Kind() != reflect.Ptr {
		t.Error("AWS SDK Client expected to be a Ptr. But found", reflect.ValueOf(c).Kind())
	}
}

func TestGetSecretValue(t *testing.T) {
	c := NewAWSSDKClient()

	c.GetSecretValue("test-name", "test-region")
}

func TestGetS3Object(t *testing.T) {
	c := NewAWSSDKClient()

	c.GetS3Object("test-bucket", "test-object", "test-region")
}

func TestGetCallerIdentity(t *testing.T) {
	c := NewAWSSDKClient()

	c.GetCallerIdentity()
}

func TestGetParameter(t *testing.T) {
	c := NewAWSSDKClient()

	c.GetParameter("test", "us-west-2")
}

func TestExecuteRequest(t *testing.T) {
	c := NewAWSSDKClient()

	c.ExecuteRequest("test-url", "test-region")
}

func TestGetSecretValueInput(t *testing.T) {
	key := "test-key"

	input := getSecretValueInput(key)

	if *input.SecretId != *aws.String(key) {
		t.Error("SecretId field was expected to be:", aws.String(key), "but got:", input.SecretId)
	}
}

func TestGetParameterInput(t *testing.T) {
	name := "test-name"

	input := getParameterInput(name)

	if *input.Name != *aws.String(name) {
		t.Error("Name field was expected to be:", aws.String(name), "but got:", input.Name)
	}

	if *input.WithDecryption != *aws.Bool(false) {
		t.Error("WithDecryption field was expected to be:", aws.Bool(false), "but got:", input.WithDecryption)
	}
}

func TestSessionWrapper(t *testing.T) {
	region := "us-east-1"

	sess := sessionWrapper(nil)

	if *sess.Config.Region != region {
		t.Error("Default session region should be:", region, "but got:", *sess.Config.Region)
	}
}
