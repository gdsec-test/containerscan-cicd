package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-github/v34/github"
	"golang.org/x/oauth2"
)

type GitHubClient interface {
	getClient() (*github.Client, error)
	getRepoStatusInput(state string) (*github.RepoStatus, error)
	getGitHubRepoNames() (string, string, error)
	getCTX() context.Context
	getCommitSHA() string
}

type GitHubAPIClient struct {
	Token       string
	TargetURL   string
	Title       string
	Description string
	GitHubURL   string
	GitHubRepo  string
	CommitSHA   string
	ctx         context.Context
}

//	NewGitHubAPIClient returns a new
func NewGitHubAPIClient(token, targetURL, gitHubURL, gitHubRepo, commitSHA string) GitHubClient {
	c := &GitHubAPIClient{
		Token:       token,
		TargetURL:   targetURL,
		GitHubURL:   gitHubURL,
		GitHubRepo:  gitHubRepo,
		CommitSHA:   commitSHA,
		Title:       "ContainerScan",
		Description: "Status for ContainerScan",
		ctx:         context.Background(),
	}
	return c
}

func (c *GitHubAPIClient) getClient() (*github.Client, error) {
	gheURL := "https://github.secureserver.net/"

	ctx := c.getCTX()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: c.Token},
	)
	tc := oauth2.NewClient(ctx, ts)

	if strings.HasPrefix(c.GitHubURL, gheURL) {
		return github.NewEnterpriseClient(gheURL, gheURL, tc)
	}

	return github.NewClient(tc), nil
}

func (c *GitHubAPIClient) getRepoStatusInput(state string) (*github.RepoStatus, error) {
	if state != "pending" && state != "success" && state != "error" && state != "failure" {
		return nil, errors.New(fmt.Sprintf("ERROR : Unsupported state '%s'", state))
	}

	return &github.RepoStatus{
		State:       String(state),
		TargetURL:   String(c.TargetURL),
		Description: String(c.Description),
		Context:     String(c.Title),
	}, nil
}

func (c *GitHubAPIClient) getGitHubRepoNames() (string, string, error) {
	s := strings.Split(c.GitHubRepo, "/")

	if len(s) != 2 {
		return "", "", errors.New(fmt.Sprintf("ERROR : Inaccurate GitHub repo name '%s'", c.GitHubRepo))
	}

	return s[0], s[1], nil
}

func (c *GitHubAPIClient) getCTX() context.Context {
	return c.ctx
}

func (c *GitHubAPIClient) getCommitSHA() string {
	return c.CommitSHA
}

func CreateRepoStatus(c GitHubClient, state string) (*github.RepoStatus, *github.Response, error) {
	client, err := c.getClient()

	if err != nil {
		return nil, nil, err
	}

	input, err := c.getRepoStatusInput(state)

	if err != nil {
		return nil, nil, err
	}

	owner, repo, err := c.getGitHubRepoNames()

	if err != nil {
		return nil, nil, err
	}

	return client.Repositories.CreateStatus(c.getCTX(), owner, repo, c.getCommitSHA(), input)
}
