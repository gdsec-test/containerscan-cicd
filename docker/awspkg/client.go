package awspkg

import (
	"net/http"
	"time"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type AWSClient interface {
	newSession() *session.Session
	GetSecretValue(secretName string, region string) (*secretsmanager.GetSecretValueOutput, error)
	GetCallerIdentity() (*sts.GetCallerIdentityOutput, error)
	GetParameter(name string) (*ssm.GetParameterOutput, error)
	ExecuteRequest(url string, region string) (*http.Response, error)
	GetS3Object(bucketName string, objectName string, region string) ([]byte, error)
}

type SDKAWSClient struct{}

func (c *SDKAWSClient) newSession() *session.Session {
	return sessionWrapper(getSession())
}

func (c *SDKAWSClient) GetSecretValue(secretName string, region string) (*secretsmanager.GetSecretValueOutput, error) {
	sess := c.newSession()
	svc := secretsmanager.New(sess, aws.NewConfig().WithRegion(region))

	input := getSecretValueInput(secretName)

	return svc.GetSecretValue(input)
}

func (c *SDKAWSClient) GetS3Object(bucketName string, objectName string, region string) ([]byte, error) {
	sess := c.newSession()
	downloader := s3manager.NewDownloader(sess)
	buff := &aws.WriteAtBuffer{}
	// Write the contents of S3 Object to the file
	_, err := downloader.Download(buff, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectName),
	})
	return buff.Bytes(), err
}

func (c *SDKAWSClient) GetCallerIdentity() (*sts.GetCallerIdentityOutput, error) {
	sess := c.newSession()
	svc := sts.New(sess, aws.NewConfig())

	input := &sts.GetCallerIdentityInput{}

	return svc.GetCallerIdentity(input)
}

func (c *SDKAWSClient) GetParameter(name string) (*ssm.GetParameterOutput, error) {
	sess := c.newSession()
	svc := ssm.New(sess, aws.NewConfig())

	input := getParameterInput(name)

	return svc.GetParameter(input)
}

func (c *SDKAWSClient) ExecuteRequest(url string, region string) (*http.Response, error) {
	sess := c.newSession()
	svc := v4.NewSigner(sess.Config.Credentials)
	req, _ := http.NewRequest("GET", url, nil)

	svc.Sign(req, nil, "execute-api", region, time.Now())

	client := new(http.Client)
	return client.Do(req)
}

// New AWS SDK Client.
func NewAWSSDKClient() AWSClient {
	c := &SDKAWSClient{}
	return c
}

func getSecretValueInput(secretName string) *secretsmanager.GetSecretValueInput {
	return &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}
}

func getParameterInput(name string) *ssm.GetParameterInput {
	return &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(false),
	}
}

func getSession() *session.Session {
	return session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
}

func sessionWrapper(sess *session.Session) *session.Session {
	if sess == nil {
		sess, _ := session.NewSessionWithOptions(session.Options{
			Config:  aws.Config{Region: aws.String("us-east-1")},
		})
		return sess
	}

	return sess
}
