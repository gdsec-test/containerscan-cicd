package test

import (
	"context"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/docker/docker/client"
)

type TestContext struct {
	ctx        context.Context
	cli        *client.Client
	err        error
	isLocal    bool
	scannerURI string
}

var testContext = TestContext{isLocal: false}

const (
	BAD_DOCKER_FILE string = "go.bad.Dockerfile"
	BAD_DOCKER_TAR  string = "bad-docker.tar"
	BAD_IMAGE       string = "containerscan-test:bad"

	GOOD_DOCKER_FILE string = "go.good.Dockerfile"
	GOOD_DOCKER_TAR  string = "good-docker.tar"
	GOOD_IMAGE       string = "containerscan-test:good"

	LOCAL_DOCKER_FILE string = "Dockerfile"
	LOCAL_DOCKER_TAR  string = "scanner-docker.tar"
	LOCAL_IMAGE       string = "container-scan:local"
)

const (
	EXIT_SUCCESS int = iota
	EXIT_FAILURE int = iota
	EXIT_BAD_ARG int = iota
)

func argValidate() {
	var tag string
	flag.StringVar(&tag, "scannerTag", "", "Tag of container-scan from Golden AMI Account.")
	flag.Parse()

	if tag == "" {
		log.Fatal("Please pass in scannerTag of scanner as an argument. \n\tOptions: local|stableprod|stabledev|1.1.1|1.1.4|...(any golden container-scan tag)\n\tex) go test -v --scannerTag=stableprod")
	} else if tag == "local" {
		testContext.scannerURI = LOCAL_IMAGE
		testContext.isLocal = true
	} else {
		testContext.scannerURI = getGoldenImageURI(tag)
	}

	log.Printf("Executing tests with '%s' version of a scanner.\n", tag)
}

func setup() {
	testContext.ctx = context.Background()
	testContext.cli, testContext.err = client.NewClientWithOpts()
	if testContext.err != nil {
		log.Fatal(testContext.err)
	}

	authConfig := getAuthConfig(getECRCredentials())

	tarCompressFile(GOOD_DOCKER_TAR, GOOD_DOCKER_FILE)
	buildTestImage(testContext.ctx, testContext.cli, GOOD_DOCKER_TAR, GOOD_DOCKER_FILE, authConfig, GOOD_IMAGE)
	log.Printf("Building '%s' as '%s'.", GOOD_DOCKER_FILE, GOOD_IMAGE)

	tarCompressFile(BAD_DOCKER_TAR, BAD_DOCKER_FILE)
	buildTestImage(testContext.ctx, testContext.cli, BAD_DOCKER_TAR, BAD_DOCKER_FILE, authConfig, BAD_IMAGE)
	log.Printf("Building '%s' as '%s'.", BAD_DOCKER_FILE, BAD_IMAGE)

	if !testContext.isLocal {
		pullDockerImage(testContext.ctx, testContext.cli, encode(authConfig), testContext.scannerURI)
	} else {
		tarCompressDirectory(LOCAL_DOCKER_TAR, "../docker/")
		buildTestImage(testContext.ctx, testContext.cli, LOCAL_DOCKER_TAR, LOCAL_DOCKER_FILE, authConfig, LOCAL_IMAGE)
	}
}

func teardown() {
	if err := os.Remove(BAD_DOCKER_TAR); err != nil {
		log.Println(err)
	}

	if err := os.Remove(GOOD_DOCKER_TAR); err != nil {
		log.Println(err)
	}

	if testContext.isLocal {
		if err := os.Remove(LOCAL_DOCKER_TAR); err != nil {
			log.Println(err)
		}
	}
}

func TestMain(m *testing.M) {
	argValidate()
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}
