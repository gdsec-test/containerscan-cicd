package main

import (
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/sts"
)

// GetSecret retrieve aws secretmanager secret
func getSecret(secretname string, region string, credentials *credentials.Credentials) (*secretsmanager.GetSecretValueOutput, error) {

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials,
	}))

	svc := secretsmanager.New(sess)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretname),
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		/*
			 To address specific error, you can import this package:
				"github.com/aws/aws-sdk-go/aws/awserr"
			and use this example:
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case secretsmanager.ErrCodeResourceNotFoundException:
					fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
				case secretsmanager.ErrCodeInvalidParameterException:
					fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
				case secretsmanager.ErrCodeInvalidRequestException:
					fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
				case secretsmanager.ErrCodeDecryptionFailure:
					fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
				case secretsmanager.ErrCodeInternalServiceError:
					fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return nil, err
		*/
	}

	return result, nil
}

//RetrieveS3File retrieve s3 file
func retrieveS3File(key string, bucket string, region string, destPath string, credentials *credentials.Credentials) ([]byte, error) {
	sess, err := session.NewSession(
		&aws.Config{
			Region:      aws.String(region),
			Credentials: credentials,
		},
	)
	if err != nil {
		return nil, err
	}
	svc := s3.New(sess)
	params := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	res, err := svc.GetObject(params)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)

}

//AssumeRole Assume aws role
func assumeRole(roleToAssumeArn string, region string) (*sts.Credentials, error) {

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		fmt.Println("NewSession Error", err)
		return nil, err
	}

	// Create a STS client
	svc := sts.New(sess)

	sessionName := "containerscanci"
	result, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         &roleToAssumeArn,
		RoleSessionName: &sessionName,
	})

	if err != nil {
		fmt.Println("AssumeRole Error", err)
		return nil, err
	}

	return result.Credentials, nil
}
