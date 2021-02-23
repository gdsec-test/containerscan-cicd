package main

import (
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
	"io"
)

// GetSecret retrieve aws secretmanager secret
func getSecret(secretname string, region string) *string {

	sess := getAWSSession()
	svc := secretsmanager.New(sess, aws.NewConfig().WithRegion(region))

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretname),
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		panic(err)

	}

	return result.SecretString
}

func callExecuteAPI(url string, region string) ([]byte, error) {

	sess := getAWSSession()
	client := new(http.Client)
	req, _ := http.NewRequest("GET", url, nil)

	signer := v4.NewSigner(sess.Config.Credentials)
	signer.Sign(req, nil, "execute-api", region, time.Now())
	resp, error := client.Do(req)
	if error != nil {
		return nil, error
	}
	b, error := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return b, error

}

func getS3Object(bucket string, key string) ([]byte, error) {
	sess := getAWSSession()
	sess.Config.Region = aws.String("us-west-2")

	svc := s3.New(sess)

	req, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		panic(err)
	}
	var reader io.Reader
	reader = req.Body
	data, error := ioutil.ReadAll(reader)

	return data, error

}

func getSSMParameter(name string) string {

	sess := getAWSSession()

	ssmsvc := ssm.New(sess, aws.NewConfig())
	param, err := ssmsvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(false),
	})

	if err != nil {
		panic(err)
	}

	value := *param.Parameter.Value
	return value
}

func getAwsAccount() string {
	sess := getAWSSession()
	svc := sts.New(sess, aws.NewConfig())

	input := &sts.GetCallerIdentityInput{}

	result, _ := svc.GetCallerIdentity(input)
	account := result.Account
	return *account

}

func getAWSSession() *session.Session {

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	if sess == nil {
		sess, _ := session.NewSessionWithOptions(session.Options{
			Profile: "default",
			Config:  aws.Config{Region: aws.String("us-east-1")},
		})
		return sess
	}
	return sess
}
