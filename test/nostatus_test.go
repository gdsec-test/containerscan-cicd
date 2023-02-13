package test

import (
	"fmt"
	"os"
	"testing"
)

func Test_nostatus_HappyPath(t *testing.T) {
	var valid bool
	var msg string

	containerConfig := getContainerConfig(
		testContext.scannerURI,
		GOOD_IMAGE,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
		"us-west-2",
		nil,
		false,
	)

	res := runDockerContainer(testContext.ctx, testContext.cli, containerConfig)

	t.Logf("\n%s", res.ContainerOutput)

	if valid, msg = assertExitCodeEqual(res.ExitCode, EXIT_SUCCESS); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "without GitHub"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, fmt.Sprintf("Scanning container image: %s", GOOD_IMAGE)); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "SUCCESS :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "FAILED :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "WARNING :"); !valid {
		t.Error(msg)
	}
}

func Test_nostatus_HappyPath_With_Unsupported_Env_AWS_DEFAULT_REGION(t *testing.T) {
	var valid bool
	var msg string
	AWS_DEFAULT_REGION := "ap-southeast-1"

	containerConfig := getContainerConfig(
		testContext.scannerURI,
		GOOD_IMAGE,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
		AWS_DEFAULT_REGION,
		nil,
		false,
	)

	res := runDockerContainer(testContext.ctx, testContext.cli, containerConfig)

	t.Logf("\n%s", res.ContainerOutput)

	if valid, msg = assertExitCodeEqual(res.ExitCode, EXIT_SUCCESS); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "without GitHub"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, fmt.Sprintf("Scanning container image: %s", GOOD_IMAGE)); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, fmt.Sprintf("AWS System parameter /AdminParams/Team/OrgType not found in region %s, set to default value non-pci", AWS_DEFAULT_REGION)); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "SUCCESS :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "FAILED :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "WARNING :"); !valid {
		t.Error(msg)
	}
}

func Test_nostatus_ErrorPath_Without_Env_AWS_ACCESS_KEY_ID_And_AWS_SESSION_TOKEN(t *testing.T) {
	var valid bool
	var msg string

	containerConfig := getContainerConfig(
		testContext.scannerURI,
		GOOD_IMAGE,
		"",
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		"",
		"us-west-2",
		nil,
		false,
	)

	res := runDockerContainer(testContext.ctx, testContext.cli, containerConfig)

	t.Logf("\n%s", res.ContainerOutput)

	if valid, msg = assertContains(res.ContainerOutput, "without GitHub"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, fmt.Sprintf("Scanning container image: %s", GOOD_IMAGE)); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "[WARNING] Required Environment variable AWS_ACCESS_KEY_ID is not provided"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "[WARNING] Required Environment variable AWS_SESSION_TOKEN is not provided"); !valid {
		t.Error(msg)
	}

	//
	// Causes an issue on CICD because of EC2 Instance Role, https://github.com/aws/aws-sdk-go#configuring-credentials
	//

	// if valid, msg = assertExitCodeEqual(res.ExitCode, EXIT_FAILURE); !valid {
	// 	t.Error(msg)
	// }

	// if valid, msg = assertContains(res.ContainerOutput, "NoCredentialProviders:"); !valid {
	// 	t.Error(msg)
	// }

	// if valid, msg = assertNotContains(res.ContainerOutput, "SUCCESS :"); !valid {
	// 	t.Error(msg)
	// }

	// if valid, msg = assertNotContains(res.ContainerOutput, "FAILED :"); !valid {
	// 	t.Error(msg)
	// }

	// if valid, msg = assertNotContains(res.ContainerOutput, "WARNING :"); !valid {
	// 	t.Error(msg)
	// }
}

func Test_nostatus_ErrorPath_Without_Env_CONTAINER(t *testing.T) {
	var valid bool
	var msg string

	containerConfig := getContainerConfig(
		testContext.scannerURI,
		"",
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
		"us-west-2",
		nil,
		false,
	)

	res := runDockerContainer(testContext.ctx, testContext.cli, containerConfig)

	t.Logf("\n%s", res.ContainerOutput)

	if valid, msg = assertExitCodeEqual(res.ExitCode, EXIT_FAILURE); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "without GitHub"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "failed to find image :latest"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "SUCCESS :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "FAILED :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "WARNING :"); !valid {
		t.Error(msg)
	}
}

func Test_nostatus_ErrorPath_With_Invalid_Env_AWS_SECRET_ACCESS_KEY(t *testing.T) {
	var valid bool
	var msg string

	containerConfig := getContainerConfig(
		testContext.scannerURI,
		GOOD_IMAGE,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		"shawnkoonkey",
		os.Getenv("AWS_SESSION_TOKEN"),
		"us-west-2",
		nil,
		false,
	)

	res := runDockerContainer(testContext.ctx, testContext.cli, containerConfig)

	t.Logf("\n%s", res.ContainerOutput)

	if valid, msg = assertExitCodeEqual(res.ExitCode, EXIT_FAILURE); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "without GitHub"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, fmt.Sprintf("Scanning container image: %s", GOOD_IMAGE)); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "SignatureDoesNotMatch:"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "SUCCESS :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "FAILED :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "WARNING :"); !valid {
		t.Error(msg)
	}
}

func Test_nostatus_SadPath(t *testing.T) {
	var valid bool
	var msg string

	containerConfig := getContainerConfig(
		testContext.scannerURI,
		BAD_IMAGE,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_SESSION_TOKEN"),
		"us-west-2",
		nil,
		false,
	)

	res := runDockerContainer(testContext.ctx, testContext.cli, containerConfig)

	t.Logf("\n%s", res.ContainerOutput)

	if valid, msg = assertExitCodeEqual(res.ExitCode, EXIT_FAILURE); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "without GitHub"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, fmt.Sprintf("Scanning container image: %s", BAD_IMAGE)); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "Compliance Issues:"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "Vulnerabilities:"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "SUCCESS :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertContains(res.ContainerOutput, "FAILED :"); !valid {
		t.Error(msg)
	}

	if valid, msg = assertNotContains(res.ContainerOutput, "WARNING :"); !valid {
		t.Error(msg)
	}
}
