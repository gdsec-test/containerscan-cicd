package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-github/v34/github"
)

type MockGitHubClient struct {
	getClientShouldError          bool
	getRepoStatusInputShouldError bool
	getGitHubRepoNamesShouldError bool
}

func (c *MockGitHubClient) getClient() (*github.Client, error) {
	var err error

	if c.getClientShouldError {
		err = errors.New("getClient ERRORED")
	}

	return &github.Client{UserAgent: "test-agent"}, err
}

func (c *MockGitHubClient) getRepoStatusInput(state string) (*github.RepoStatus, error) {
	var err error

	if c.getRepoStatusInputShouldError {
		err = errors.New("getRepoStatusInput ERRORED")
	}

	return &github.RepoStatus{State: String("test-state")}, err
}

func (c *MockGitHubClient) getGitHubRepoNames() (string, string, error) {
	var err error

	if c.getGitHubRepoNamesShouldError {
		err = errors.New("getClient ERRORED")
	}

	return "test-owner", "test-repo", err
}

func (c *MockGitHubClient) getCTX() context.Context {
	return context.Background()
}

func (c *MockGitHubClient) getCommitSHA() string {
	return "test-SHA"
}

func NewMockGitHubClient(getClientShouldError, getRepoStatusInputShouldError, getGitHubRepoNamesShouldError bool) GitHubClient {
	return &MockGitHubClient{
		getClientShouldError:          getClientShouldError,
		getRepoStatusInputShouldError: getRepoStatusInputShouldError,
		getGitHubRepoNamesShouldError: getGitHubRepoNamesShouldError,
	}
}

func TestGetClient_shouldReturnGitHubEnterpriseClient(t *testing.T) {
	githubURL := "https://github.secureserver.net/"
	c := NewGitHubAPIClient("sdfasdfasdf", "sadfasdfas", githubURL, "asdfsdfa", "asdfasdfas")

	res, _ := c.getClient()

	if !strings.HasSuffix(res.BaseURL.String(), "api/v3/") {
		t.Error("Client expected to be enterprise Client.")
	}
}

func TestGetClient_shouldReturnGitHubCludClient(t *testing.T) {
	githubURL := "https://github.com/"
	c := NewGitHubAPIClient("", "", githubURL, "", "")

	res, _ := c.getClient()

	if strings.HasSuffix(res.BaseURL.String(), "api/v3/") {
		t.Error("Client expected to be GHC Client.")
	}
}

func TestGetRepoStatusInput_shouldNotErrorWhenStateKnown(t *testing.T) {
	states := []string{"pending", "success", "error", "failure"}
	url := "test-url"
	c := NewGitHubAPIClient("", url, "", "", "")

	for _, s := range states {
		res, err := c.getRepoStatusInput(s)

		if err != nil {
			t.Error("getRepoStatusInput returned unexpected error")
		} else {
			if *(res.TargetURL) != url {
				t.Error("Expected:", url, "but got:", *(res.TargetURL))
			}
		}
	}
}

func TestGetRepoStatusInput_shouldErrorWhenState_random(t *testing.T) {
	states := []string{"random", "ok", "fail", "warning"}
	url := "test-url"
	c := NewGitHubAPIClient("", url, "", "", "")

	for _, s := range states {
		_, err := c.getRepoStatusInput(s)

		if err == nil {
			t.Error("getRepoStatusInput did not return expected error")
		}
	}
}

func TestGetGitHubRepoName_shouldErrorIfSplitCount_notTwo(t *testing.T) {
	githubRepos := []string{"test-repo", "org/test-repo/2"}
	for _, githubRepo := range githubRepos {
		c := NewGitHubAPIClient("", "", "", githubRepo, "")

		_, _, err := c.getGitHubRepoNames()

		if err == nil {
			t.Error("getGitHubRepoNames did not return expected error")
		}
	}
}

func TestGetGitHubRepoName_shouldNotErrorIfSplitCount_two(t *testing.T) {
	githubRepo := "gdcorp-infosec/containerscan-cicd"
	c := NewGitHubAPIClient("", "", "", githubRepo, "")

	_, _, err := c.getGitHubRepoNames()

	if err != nil {
		t.Error("getGitHubRepoNames returned unexpected error")
	}
}

func TestGetCommitSHA(t *testing.T) {
	sha := "test-SHA"
	c := NewGitHubAPIClient("", "", "", "", sha)

	if c.getCommitSHA() != sha {
		t.Error("Expected :", sha, "but got :", c.getCommitSHA())
	}
}

func TestCreateRepoStatus_shouldErrorWhenGetClient_error(t *testing.T) {
	c := NewMockGitHubClient(true, false, false)

	_, _, err := CreateRepoStatus(c, "test-State")
	if err == nil {
		t.Error("CreateRepoStatus did not return expected error")
	}
}

func TestCreateRepoStatus_shouldErrorWhenGetRepoStatusInput_error(t *testing.T) {
	c := NewMockGitHubClient(false, true, false)

	_, _, err := CreateRepoStatus(c, "test-State")
	if err == nil {
		t.Error("CreateRepoStatus did not return expected error")
	}
}

func TestCreateRepoStatus_shouldErrorWhenGetGitHubRepoNames_error(t *testing.T) {
	c := NewMockGitHubClient(false, false, true)

	_, _, err := CreateRepoStatus(c, "test-State")
	if err == nil {
		t.Error("CreateRepoStatus did not return expected error")
	}
}
