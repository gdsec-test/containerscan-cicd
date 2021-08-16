package test

import (
	"encoding/base64"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

type ECRCredentials struct {
	Username string
	Password string
}

func getECRCredentials() ECRCredentials {
	sess, err := session.NewSession(aws.NewConfig().WithRegion(GOLDEN_AMI_REGION))
	if err != nil {
		log.Fatal(err)
	}

	svc := ecr.New(sess)

	res, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		log.Fatal(err)
	}

	message := *res.AuthorizationData[0].AuthorizationToken
	sDec, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		log.Fatal(err)
	}

	creds := strings.Split(string(sDec), ":")

	return ECRCredentials{Username: creds[0], Password: creds[1]}
}
