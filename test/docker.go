package test

import (
	"context"
	"io"
	"log"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type ContainerRunResult struct {
	ContainerOutput string
	ExitCode        int
}

type GitHubStatusParams struct {
	TargetURL  string
	GitHubURL  string
	GitHubRepo string
	CommitSHA  string
	PAT        string
}

func getAuthConfig(ecrCreds ECRCredentials) types.AuthConfig {
	return types.AuthConfig{
		Username:      ecrCreds.Username,
		Password:      ecrCreds.Password,
		ServerAddress: GOLDEN_AMI_REPO,
	}
}

func pullDockerImage(ctx context.Context, cli *client.Client, encAuth string, imageURI string) {
	reader, err := cli.ImagePull(
		ctx,
		imageURI,
		types.ImagePullOptions{RegistryAuth: encAuth},
	)

	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()
	io.Copy(os.Stdout, reader)
}

func getContainerConfig(imageURI, targetImage, awsAccessKeyID, awsSecretAccessKey, awsSessionToken, awsDefaultRegion string, githubParams *GitHubStatusParams, isJson bool) container.Config {
	envs := []string{}

	if targetImage != "" {
		envs = append(envs, "CONTAINER="+targetImage)
	}

	if awsAccessKeyID != "" {
		envs = append(envs, "AWS_ACCESS_KEY_ID="+awsAccessKeyID)
	}

	if awsSecretAccessKey != "" {
		envs = append(envs, "AWS_SECRET_ACCESS_KEY="+awsSecretAccessKey)
	}

	if awsSessionToken != "" {
		envs = append(envs, "AWS_SESSION_TOKEN="+awsSessionToken)
	}

	if awsDefaultRegion != "" {
		envs = append(envs, "AWS_DEFAULT_REGION="+awsDefaultRegion)
	}

	if isJson {
		envs = append(envs, "FORMAT=json")
	}

	if githubParams == nil {
		envs = append(envs, "SCANNER_STATUS=nostatus")
	} else {
		if githubParams.TargetURL != "" {
			envs = append(envs, "TARGET_URL="+githubParams.TargetURL)
		}

		if githubParams.GitHubURL != "" {
			envs = append(envs, "GITHUB_URL="+githubParams.GitHubURL)
		}

		if githubParams.GitHubRepo != "" {
			envs = append(envs, "GITHUB_REPO="+githubParams.GitHubRepo)
		}

		if githubParams.CommitSHA != "" {
			envs = append(envs, "COMMIT_SHA="+githubParams.CommitSHA)
		}

		if githubParams.PAT != "" {
			envs = append(envs, "PAT="+githubParams.PAT)
		}
	}

	return container.Config{
		Image:        imageURI,
		User:         "root",
		Env:          envs,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true, // Must be enabled to get accurate stdout without binary garbage
	}
}

func runDockerContainer(ctx context.Context, cli *client.Client, containerConfig container.Config) ContainerRunResult {
	var statusCode int

	resp, err := cli.ContainerCreate(
		ctx,
		&containerConfig,
		&container.HostConfig{
			Binds: []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
		}, nil, nil, "")

	if err != nil {
		log.Fatal(err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		log.Fatal(err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			log.Fatal(err)
		}
	case stat := <-statusCh:
		statusCode = int(stat.StatusCode)
	}

	defer func() {
		if err := cli.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{}); err != nil {
			log.Fatal(err)
		}
	}()

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		log.Fatal(err)
	}

	containerOutput := new(strings.Builder)
	io.Copy(containerOutput, out)
	defer out.Close()

	return ContainerRunResult{ContainerOutput: containerOutput.String(), ExitCode: statusCode}
}

func buildTestImage(ctx context.Context, cli *client.Client, tarName string, dockerfileName string, authConfig types.AuthConfig, targetImage string) {
	dockerContext, err := os.Open(tarName)
	if err != nil {
		log.Fatal(err)
	}
	defer dockerContext.Close()

	buildResp, err := cli.ImageBuild(ctx, dockerContext, types.ImageBuildOptions{
		Tags:        []string{targetImage},
		Dockerfile:  dockerfileName,
		AuthConfigs: map[string]types.AuthConfig{GOLDEN_AMI_REPO: authConfig},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer buildResp.Body.Close()

	buildOutput := new(strings.Builder)

	io.Copy(buildOutput, buildResp.Body)
	defer buildResp.Body.Close()

	if strings.Contains(buildOutput.String(), "errorDetail") {
		log.Fatal(buildOutput.String())
	}
}
