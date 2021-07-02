package circleci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	queryLimit = 100 // maximum that CircleCI allows
)

var (
	defaultBaseURL = &url.URL{Host: "circleci.com", Scheme: "https", Path: "/api/v1.1/"}
	baseURLV2      = &url.URL{Host: "circleci.com", Scheme: "https", Path: "/api/v2/"}
	defaultLogger  = log.New(os.Stderr, "", log.LstdFlags)
)

// APIVersion denotes the version of the API to be used by the client.
type APIVersion uint8

const (
	APIVersionNone APIVersion = iota
	APIVersion11
	APIVersion2
)

// String returns a string form of the version.
func (v APIVersion) String() string {
	return [...]string{"none", "APIv1.1", "APIv2"}[v]
}

// Logger is a minimal interface for injecting custom logging logic for debug logs
type Logger interface {
	Printf(fmt string, args ...interface{})
}

// APIError represents an error from CircleCI
type APIError struct {
	HTTPStatusCode int
	Message        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%d: %s", e.HTTPStatusCode, e.Message)
}

type InvalidVersionError struct {
	version APIVersion
}

func (e *InvalidVersionError) Error() string {
	return fmt.Sprintf("incorrect version: %s", e.version)
}

func newInvalidVersionError(version APIVersion) *InvalidVersionError {
	return &InvalidVersionError{version: version}
}

// Client is a CircleCI client
// Its zero value is a usable client for examining public CircleCI repositories
type Client struct {
	BaseURL    *url.URL     // CircleCI API endpoint (defaults to DefaultEndpoint)
	Token      string       // CircleCI API token (needed for private repositories and mutative actions)
	HTTPClient *http.Client // HTTPClient to use for connecting to CircleCI (defaults to http.DefaultClient)

	Debug   bool   // debug logging enabled
	Logger  Logger // logger to send debug messages on (if enabled), defaults to logging to stderr with the standard flags
	Version APIVersion
}

// NewClient returns a new CircleCI client by settings the baseURL depending on the API version passed.
func NewClient(token string, version APIVersion) (*Client, error) {
	var baseURL *url.URL
	switch version {
	case APIVersion11:
		baseURL = defaultBaseURL
	case APIVersion2:
		baseURL = baseURLV2
	default:
		return nil, newInvalidVersionError(version)
	}
	return &Client{
		Token:   token,
		BaseURL: baseURL,
		Version: version,
	}, nil
}

func (c *Client) baseURL() *url.URL {
	if c.BaseURL == nil {
		return defaultBaseURL
	}

	return c.BaseURL
}

func (c *Client) client() *http.Client {
	if c.HTTPClient == nil {
		return http.DefaultClient
	}

	return c.HTTPClient
}

func (c *Client) logger() Logger {
	if c.Logger == nil {
		return defaultLogger
	}

	return c.Logger
}

func (c *Client) debug(format string, args ...interface{}) {
	if c.Debug {
		c.logger().Printf(format, args...)
	}
}

func (c *Client) debugRequest(req *http.Request) {
	if c.Debug {
		out, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			c.debug("error debugging request %+v: %s", req, err)
		}
		c.debug("request:\n%+v", string(out))
	}
}

func (c *Client) debugResponse(resp *http.Response) {
	if c.Debug {
		out, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.debug("error debugging response %+v: %s", resp, err)
		}
		c.debug("response:\n%+v", string(out))
	}
}

type nopCloser struct {
	io.Reader
}

func (n nopCloser) Close() error { return nil }

func (c *Client) request(ctx context.Context, method, path string, responseStruct interface{}, params url.Values, bodyStruct interface{}) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("circle-token", c.Token)

	u := c.baseURL().ResolveReference(&url.URL{Path: path, RawQuery: params.Encode()})

	c.debug("building request for %s", u)

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return err
	}

	if bodyStruct != nil {
		b, err := json.Marshal(bodyStruct)
		if err != nil {
			return err
		}

		req.Body = nopCloser{bytes.NewBuffer(b)}
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Circle-Token", c.Token)

	c.debugRequest(req)

	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.debugResponse(resp)

	if resp.StatusCode >= 300 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return &APIError{HTTPStatusCode: resp.StatusCode, Message: "unable to parse response: %s"}
		}

		if len(body) > 0 {
			message := struct {
				Message string `json:"message"`
			}{}
			err = json.Unmarshal(body, &message)
			if err != nil {
				return &APIError{
					HTTPStatusCode: resp.StatusCode,
					Message:        fmt.Sprintf("unable to parse API response: %s", err),
				}
			}
			return &APIError{HTTPStatusCode: resp.StatusCode, Message: message.Message}
		}

		return &APIError{HTTPStatusCode: resp.StatusCode}
	}

	if responseStruct != nil {
		err = json.NewDecoder(resp.Body).Decode(responseStruct)
		if err != nil {
			return err
		}
	}

	return nil
}

// Me returns information about the current user
func (c *Client) MeWithContext(ctx context.Context) (*User, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	user := &User{}

	err := c.request(context.Background(), "GET", "me", user, nil, nil)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *Client) Me() (*User, error) {
	return c.MeWithContext(context.Background())
}

// ListProjectsWithContext returns the list of projects the user is watching
func (c *Client) ListProjects() ([]*Project, error) {
	return c.ListProjectsWithContext(context.Background())
}

// ListProjectsWithContext is the same as ListProjects with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListProjectsWithContext(ctx context.Context) ([]*Project, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	projects := []*Project{}

	err := c.request(ctx, "GET", "projects", &projects, nil, nil)
	if err != nil {
		return nil, err
	}

	for _, project := range projects {
		if err := cleanupProject(project); err != nil {
			return nil, err
		}
	}

	return projects, nil
}

// EnableProject enables a project - generates a deploy SSH key used to checkout the Github repo.
// The Github user tied to the Circle API Token must have "admin" access to the repo.
func (c *Client) EnableProject(vcsType VcsType, account, repo string) error {
	return c.EnableProjectWithContext(context.Background(), vcsType, account, repo)
}

// EnableProjectWithContext is the same as EnableProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) EnableProjectWithContext(ctx context.Context, vcsType VcsType, account, repo string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/enable", vcsType, account, repo), nil, nil, nil)
}

// DisableProject disables a project
func (c *Client) DisableProject(vcsType VcsType, account, repo string) error {
	return c.DisableProjectWithContext(context.Background(), vcsType, account, repo)
}

// DisableProjectWithContext is the same as DisableProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) DisableProjectWithContext(ctx context.Context, vcsType VcsType, account, repo string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.request(ctx, "DELETE", fmt.Sprintf("project/%s/%s/%s/enable", vcsType, account, repo), nil, nil, nil)
}

// FollowProject follows a project
func (c *Client) FollowProject(vcsType VcsType, account, repo string) (*Project, error) {
	return c.FollowProjectWithContext(context.Background(), vcsType, account, repo)
}

// FollowProjectWithContext is the same as FollowProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) FollowProjectWithContext(ctx context.Context, vcsType VcsType, account, repo string) (*Project, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	project := &Project{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/follow", vcsType, account, repo), project, nil, nil)
	if err != nil {
		return nil, err
	}

	if err := cleanupProject(project); err != nil {
		return nil, err
	}

	return project, nil
}

// UnfollowProject unfollows a project
func (c *Client) UnfollowProject(vcsType VcsType, account, repo string) (*Project, error) {
	return c.UnfollowProjectWithContext(context.Background(), vcsType, account, repo)
}

// UnfollowProjectWithContext is the same as UnfollowProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) UnfollowProjectWithContext(ctx context.Context, vcsType VcsType, account, repo string) (*Project, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	project := &Project{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/unfollow", vcsType, account, repo), project, nil, nil)
	if err != nil {
		return nil, err
	}

	if err := cleanupProject(project); err != nil {
		return nil, err
	}

	return project, nil
}

// GetProject retrieves a specific project
// Returns nil of the project is not in the list of watched projects
func (c *Client) GetProject(account, repo string) (*Project, error) {
	return c.GetProjectWithContext(context.Background(), account, repo)
}

// GetProjectWithContext is the same as GetProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) GetProjectWithContext(ctx context.Context, account, repo string) (*Project, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	projects, err := c.ListProjectsWithContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, project := range projects {
		if account == project.Username && repo == project.Reponame {
			return project, nil
		}
	}

	return nil, nil
}

func (c *Client) recentBuilds(ctx context.Context, path string, params url.Values, limit, offset int) ([]*Build, error) {
	allBuilds := []*Build{}

	if params == nil {
		params = url.Values{}
	}

	fetchAll := limit == -1
	for {
		builds := []*Build{}

		if fetchAll {
			limit = queryLimit + 1
		}

		l := limit
		if l > queryLimit {
			l = queryLimit
		}

		params.Set("limit", strconv.Itoa(l))
		params.Set("offset", strconv.Itoa(offset))

		err := c.request(ctx, "GET", path, &builds, params, nil)
		if err != nil {
			return nil, err
		}
		allBuilds = append(allBuilds, builds...)

		offset += len(builds)
		limit -= len(builds)
		if len(builds) < queryLimit || limit == 0 {
			break
		}
	}

	return allBuilds, nil
}

// ListRecentBuilds fetches the list of recent builds for all repositories the user is watching
// If limit is -1, fetches all builds
func (c *Client) ListRecentBuilds(limit, offset int) ([]*Build, error) {
	return c.ListRecentBuildsWithContext(context.Background(), limit, offset)
}

// ListRecentBuildsWithContext is the same as ListRecentBuilds with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListRecentBuildsWithContext(ctx context.Context, limit, offset int) ([]*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	return c.recentBuilds(ctx, "recent-builds", nil, limit, offset)
}

// ListRecentBuildsForProject fetches the list of recent builds for the given repository
// The status and branch parameters are used to further filter results if non-empty
// If limit is -1, fetches all builds
func (c *Client) ListRecentBuildsForProject(vcsType VcsType, account, repo, branch, status string, limit, offset int) ([]*Build, error) {
	return c.ListRecentBuildsForProjectWithContext(context.Background(), vcsType, account, repo, branch, status, limit, offset)
}

// ListRecentBuildsForProjectWithContext is the same as ListRecentBuildsForProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListRecentBuildsForProjectWithContext(ctx context.Context, vcsType VcsType, account, repo, branch, status string, limit, offset int) ([]*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	path := fmt.Sprintf("project/%s/%s/%s", vcsType, account, repo)
	if branch != "" {
		path = fmt.Sprintf("%s/tree/%s", path, branch)
	}

	params := url.Values{}
	if status != "" {
		params.Set("filter", status)
	}

	return c.recentBuilds(ctx, path, params, limit, offset)
}

// GetBuild fetches a given build by number
func (c *Client) GetBuild(vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	return c.GetBuildWithContext(context.Background(), vcsType, account, repo, buildNum)
}

// GetBuildWithContext is the same as GetBuild with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) GetBuildWithContext(ctx context.Context, vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	build := &Build{}

	err := c.request(ctx, "GET", fmt.Sprintf("project/%s/%s/%s/%d", vcsType, account, repo, buildNum), build, nil, nil)
	if err != nil {
		return nil, err
	}

	return build, nil
}

// ListBuildArtifacts fetches the build artifacts for the given build
func (c *Client) ListBuildArtifacts(vcsType VcsType, account, repo string, buildNum int) ([]*Artifact, error) {
	return c.ListBuildArtifactsWithContext(context.Background(), vcsType, account, repo, buildNum)
}

// ListBuildArtifactsWithContext is the same as ListBuildArtifacts with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListBuildArtifactsWithContext(ctx context.Context, vcsType VcsType, account, repo string, buildNum int) ([]*Artifact, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	var artifacts []*Artifact

	err := c.request(ctx, "GET", fmt.Sprintf("project/%s/%s/%s/%d/artifacts", vcsType, account, repo, buildNum), &artifacts, nil, nil)
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

// ListTestMetadata fetches the build metadata for the given build
func (c *Client) ListTestMetadata(vcsType VcsType, account, repo string, buildNum int) ([]*TestMetadata, error) {
	return c.ListTestMetadataWithContext(context.Background(), vcsType, account, repo, buildNum)
}

// ListTestMetadataWithContext is the same as ListTestMetadata with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListTestMetadataWithContext(ctx context.Context, vcsType VcsType, account, repo string, buildNum int) ([]*TestMetadata, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	metadata := struct {
		Tests []*TestMetadata `json:"tests"`
	}{}

	err := c.request(ctx, "GET", fmt.Sprintf("project/%s/%s/%s/%d/tests", vcsType, account, repo, buildNum), &metadata, nil, nil)
	if err != nil {
		return nil, err
	}

	return metadata.Tests, nil
}

// AddSSHUser adds the user associated with the API token to the list of valid
// SSH users for a build.
//
// The API token being used must be a user API token
func (c *Client) AddSSHUser(vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	return c.AddSSHUserWithContext(context.Background(), vcsType, account, repo, buildNum)
}

// AddSSHUserWithContext is the same as AddSSHUser with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) AddSSHUserWithContext(ctx context.Context, vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	build := &Build{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/%d/ssh-users", vcsType, account, repo, buildNum), build, nil, nil)
	if err != nil {
		return nil, err
	}

	return build, nil
}

// Build triggers a new build for the given project for the given
// project on the given branch.
// Returns the new build information
func (c *Client) Build(vcsType VcsType, account, repo, branch string) (*Build, error) {
	return c.BuildWithContext(context.Background(), vcsType, account, repo, branch)
}

// BuildWithContext is the same as Build with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) BuildWithContext(ctx context.Context, vcsType VcsType, account, repo, branch string) (*Build, error) {
	return c.BuildOptsWithContext(ctx, vcsType, account, repo, branch, nil)
}

// ParameterizedBuild triggers a new parameterized build for the given
// project on the given branch, Marshaling the struct into json and passing
// in the post body.
// Returns the new build information
func (c *Client) ParameterizedBuild(vcsType VcsType, account, repo, branch string, buildParameters map[string]string) (*Build, error) {
	return c.ParameterizedBuildWithContext(context.Background(), vcsType, account, repo, branch, buildParameters)
}

// ParametrizedBuildWithContext is the same as ParametrizedBuild with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ParameterizedBuildWithContext(ctx context.Context, vcsType VcsType, account, repo, branch string, buildParameters map[string]string) (*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	opts := map[string]interface{}{"build_parameters": buildParameters}
	return c.BuildOptsWithContext(ctx, vcsType, account, repo, branch, opts)
}

// BuildOpts triggeres a new build for the givent project on the given
// branch, Marshaling the struct into json and passing
// in the post body.
// Returns the new build information
func (c *Client) BuildOpts(vcsType VcsType, account, repo, branch string, opts map[string]interface{}) (*Build, error) {
	return c.BuildOptsWithContext(context.Background(), vcsType, account, repo, branch, opts)
}

// BuildOptsWithContext is the same as BuildOpts with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) BuildOptsWithContext(ctx context.Context, vcsType VcsType, account, repo, branch string, opts map[string]interface{}) (*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	build := &Build{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/tree/%s", vcsType, account, repo, branch), build, nil, opts)
	if err != nil {
		return nil, err
	}

	return build, nil
}

// BuildByProjectBranch triggers a build by project (this is the only way to trigger a build for project using Circle
// 2.1) by branch
//
// NOTE: this endpoint is only available in the CircleCI API v1.1. in order to call it, you must instantiate the Client
// object with the following value for BaseURL: &url.URL{Host: "circleci.com", Scheme: "https", Path: "/api/v1.1/"}
func (c *Client) BuildByProjectBranch(vcsType VcsType, account, repo, branch string) error {
	return c.BuildByProjectBranchWithContext(context.Background(), vcsType, account, repo, branch)
}

// BuildByProjectBranchWithContext is the same as BuildByProjectBranch with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) BuildByProjectBranchWithContext(ctx context.Context, vcsType VcsType, account, repo, branch string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.buildProject(ctx, vcsType, account, repo, map[string]interface{}{
		"branch": branch,
	})
}

// BuildByProjectRevision triggers a build by project (this is the only way to trigger a build for project using Circle
// 2.1) by revision
//
// NOTE: this endpoint is only available in the CircleCI API v1.1. in order to call it, you must instantiate the Client
// object with the following value for BaseURL: &url.URL{Host: "circleci.com", Scheme: "https", Path: "/api/v1.1/"}
func (c *Client) BuildByProjectRevision(vcsType VcsType, account string, repo string, revision string) error {
	return c.BuildByProjectRevisionWithContext(context.Background(), vcsType, account, repo, revision)
}

// BuildByProjectRevisionWithContext is the same as BuildByProjectRevision with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) BuildByProjectRevisionWithContext(ctx context.Context, vcsType VcsType, account, repo, revision string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.buildProject(ctx, vcsType, account, repo, map[string]interface{}{
		"revision": revision,
	})
}

// BuildByProjectTag triggers a build by project (this is the only way to trigger a build for project using Circle 2.1)
// using a tag reference
//
// NOTE: this endpoint is only available in the CircleCI API v1.1. in order to call it, you must instantiate the Client
// object with the following value for BaseURL: &url.URL{Host: "circleci.com", Scheme: "https", Path: "/api/v1.1/"}
func (c *Client) BuildByProjectTag(vcsType VcsType, account, repo, tag string) error {
	return c.BuildByProjectTagWithContext(context.Background(), vcsType, account, repo, tag)
}

// BuildByProjectTagWithContext is the same as BuildByProjectTag with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) BuildByProjectTagWithContext(ctx context.Context, vcsType VcsType, account, repo, tag string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.buildProject(ctx, vcsType, account, repo, map[string]interface{}{
		"tag": tag,
	})
}

// BuildByProject triggers a build by project (this is the only way to trigger a build for project using Circle 2.1)
// you can set revision and/or tag/branch
// this is useful if you need to trigger a build from a PR froma fork, in which you need to set the revision and the
// branch in this format `pull/PR_NUMBER`
// ie.:
//  map[string]interface{}{
// 		"revision": "8afbae7ec63b2b0f2786740d03161dbb08ba55f5",
//		"branch"  : "pull/1234",
// 	})
//
// NOTE: this endpoint is only available in the CircleCI API v1.1. in order to call it, you must instantiate the Client
// object with the following value for BaseURL: &url.URL{Host: "circleci.com", Scheme: "https", Path: "/api/v1.1/"}
func (c *Client) BuildByProject(vcsType VcsType, account string, repo string, opts map[string]interface{}) error {
	return c.BuildByProjectWithContext(context.Background(), vcsType, account, repo, opts)
}

// BuildByProjectWithContext is the same as BuildByProject with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) BuildByProjectWithContext(ctx context.Context, vcsType VcsType, account, repo string, opts map[string]interface{}) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.buildProject(ctx, vcsType, account, repo, opts)
}

func (c *Client) buildProject(ctx context.Context, vcsType VcsType, account string, repo string, opts map[string]interface{}) error {
	resp := &BuildByProjectResponse{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/build", vcsType, account, repo), resp, nil, opts)
	if err != nil {
		return err
	}

	if resp.Status != 200 || resp.Body != "Build created" {
		return fmt.Errorf("unexpected build info in response %+v", resp)
	}
	return nil
}

// RetryBuild triggers a retry of the specified build
// Returns the new build information
func (c *Client) RetryBuild(vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	return c.RetryBuildWithContext(context.Background(), vcsType, account, repo, buildNum)
}

// RetryBuildWithContext is the same as RetryBuild with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) RetryBuildWithContext(ctx context.Context, vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	build := &Build{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/%d/retry", vcsType, account, repo, buildNum), build, nil, nil)
	if err != nil {
		return nil, err
	}

	return build, nil
}

// CancelBuild triggers a cancel of the specified build
// Returns the new build information
func (c *Client) CancelBuild(vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	return c.CancelBuildWithContext(context.Background(), vcsType, account, repo, buildNum)
}

// CancelBuildWithContext is the same as CancelBuild with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) CancelBuildWithContext(ctx context.Context, vcsType VcsType, account, repo string, buildNum int) (*Build, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	build := &Build{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/%d/cancel", vcsType, account, repo, buildNum), build, nil, nil)
	if err != nil {
		return nil, err
	}

	return build, nil
}

// ClearCache clears the cache of the specified project
// Returns the status returned by CircleCI
func (c *Client) ClearCache(vcsType VcsType, account, repo string) (string, error) {
	return c.ClearCacheWithContext(context.Background(), vcsType, account, repo)
}

// ClearCacheWithContext is the same as ClearCache with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ClearCacheWithContext(ctx context.Context, vcsType VcsType, account, repo string) (string, error) {
	if c.Version < APIVersion11 {
		return "", newInvalidVersionError(c.Version)
	}
	status := &struct {
		Status string `json:"status"`
	}{}

	err := c.request(ctx, "DELETE", fmt.Sprintf("project/%s/%s/%s/build-cache", vcsType, account, repo), status, nil, nil)
	if err != nil {
		return "", err
	}

	return status.Status, nil
}

// AddEnvVar adds a new environment variable to the specified project
// Returns the added env var (the value will be masked)
func (c *Client) AddEnvVar(vcsType VcsType, account, repo, name, value string) (*EnvVar, error) {
	return c.AddEnvVarWithContext(context.Background(), vcsType, account, repo, name, value)
}

// AddEnvVarWithContext is the same as AddEnvVar with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) AddEnvVarWithContext(ctx context.Context, vcsType VcsType, account, repo, name, value string) (*EnvVar, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	envVar := &EnvVar{}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/envvar", vcsType, account, repo), envVar, nil, &EnvVar{Name: name, Value: value})
	if err != nil {
		return nil, err
	}

	return envVar, nil
}

// ListEnvVars list environment variable to the specified project
// Returns the env vars (the value will be masked)
func (c *Client) ListEnvVars(vcsType VcsType, account, repo string) ([]EnvVar, error) {
	return c.ListEnvVarsWithContext(context.Background(), vcsType, account, repo)
}

// ListEnvVarsWithContext is the same as ListEnvVars with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListEnvVarsWithContext(ctx context.Context, vcsType VcsType, account, repo string) ([]EnvVar, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	envVar := []EnvVar{}

	err := c.request(ctx, "GET", fmt.Sprintf("project/%s/%s/%s/envvar", vcsType, account, repo), &envVar, nil, nil)
	if err != nil {
		return nil, err
	}

	return envVar, nil
}

// DeleteEnvVar deletes the specified environment variable from the project
func (c *Client) DeleteEnvVar(vcsType VcsType, account, repo, name string) error {
	return c.DeleteEnvVarWithContext(context.Background(), vcsType, account, repo, name)
}

// DeleteEnvVarWithContext is the same as DeleteEnvVar with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) DeleteEnvVarWithContext(ctx context.Context, vcsType VcsType, account, repo, name string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.request(ctx, "DELETE", fmt.Sprintf("project/%s/%s/%s/envvar/%s", vcsType, account, repo, name), nil, nil, nil)
}

// AddSSHKey adds a new SSH key to the project
func (c *Client) AddSSHKey(vcsType VcsType, account, repo, hostname, privateKey string) error {
	return c.AddSSHKeyWithContext(context.Background(), vcsType, account, repo, hostname, privateKey)
}

// AddSSHKeyWithContext is the same as AddSSHKey with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) AddSSHKeyWithContext(ctx context.Context, vcsType VcsType, account, repo, hostname, privateKey string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	key := &struct {
		Hostname   string `json:"hostname"`
		PrivateKey string `json:"private_key"`
	}{hostname, privateKey}
	return c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/ssh-key", vcsType, account, repo), nil, nil, key)
}

// GetActionOutputs fetches the output for the given action
// If the action has no output, returns nil
func (c *Client) GetActionOutputs(a *Action) ([]*Output, error) {
	return c.GetActionOutputsWithContext(context.Background(), a)
}

// GetActionOutputWithContext is the same as GetActionOutput with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) GetActionOutputsWithContext(ctx context.Context, a *Action) ([]*Output, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	if !a.HasOutput || a.OutputURL == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", a.OutputURL, nil)
	if err != nil {
		return nil, err
	}

	c.debugRequest(req)

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	c.debugResponse(resp)

	output := []*Output{}
	if err = json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, err
	}

	return output, nil
}

// ListCheckoutKeys fetches the checkout keys associated with the given project
func (c *Client) ListCheckoutKeys(vcsType VcsType, account, repo string) ([]*CheckoutKey, error) {
	return c.ListCheckoutKeysWithContext(context.Background(), vcsType, account, repo)
}

// ListCheckoutKeysWithContext is the same as ListCheckoutKeys with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) ListCheckoutKeysWithContext(ctx context.Context, vcsType VcsType, account, repo string) ([]*CheckoutKey, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	checkoutKeys := []*CheckoutKey{}

	err := c.request(ctx, "GET", fmt.Sprintf("project/%s/%s/%s/checkout-key", vcsType, account, repo), &checkoutKeys, nil, nil)
	if err != nil {
		return nil, err
	}

	return checkoutKeys, nil
}

// CreateCheckoutKey creates a new checkout key for a project
// Valid key types are currently deploy-key and github-user-key
//
// The github-user-key type requires that the API token being used be a user API token
func (c *Client) CreateCheckoutKey(vcsType VcsType, account, repo, keyType string) (*CheckoutKey, error) {
	return c.CreateCheckoutKeyWithContext(context.Background(), vcsType, account, repo, keyType)
}

// CreateCheckoutKeyWithContext is the same as CreateCheckoutKey with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) CreateCheckoutKeyWithContext(ctx context.Context, vcsType VcsType, account, repo, keyType string) (*CheckoutKey, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	checkoutKey := &CheckoutKey{}

	body := struct {
		KeyType string `json:"type"`
	}{KeyType: keyType}

	err := c.request(ctx, "POST", fmt.Sprintf("project/%s/%s/%s/checkout-key", vcsType, account, repo), checkoutKey, nil, body)
	if err != nil {
		return nil, err
	}

	return checkoutKey, nil
}

// GetCheckoutKey fetches the checkout key for the given project by fingerprint
func (c *Client) GetCheckoutKey(vcsType VcsType, account, repo, fingerprint string) (*CheckoutKey, error) {
	return c.GetCheckoutKeyWithContext(context.Background(), vcsType, account, repo, fingerprint)
}

// GetCheckoutKeyWithContext is the same as GetCheckoutKey with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) GetCheckoutKeyWithContext(ctx context.Context, vcsType VcsType, account, repo, fingerprint string) (*CheckoutKey, error) {
	if c.Version < APIVersion11 {
		return nil, newInvalidVersionError(c.Version)
	}
	checkoutKey := &CheckoutKey{}

	err := c.request(ctx, "GET", fmt.Sprintf("project/%s/%s/%s/checkout-key/%s", vcsType, account, repo, fingerprint), &checkoutKey, nil, nil)
	if err != nil {
		return nil, err
	}

	return checkoutKey, nil
}

// DeleteCheckoutKey fetches the checkout key for the given project by fingerprint
func (c *Client) DeleteCheckoutKey(vcsType VcsType, account, repo, fingerprint string) error {
	return c.DeleteCheckoutKeyWithContext(context.Background(), vcsType, account, repo, fingerprint)
}

// GetCheckoutKeyWithContext is the same as GetCheckoutKey with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) DeleteCheckoutKeyWithContext(ctx context.Context, vcsType VcsType, account, repo, fingerprint string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	return c.request(ctx, "DELETE", fmt.Sprintf("project/%s/%s/%s/checkout-key/%s", vcsType, account, repo, fingerprint), nil, nil, nil)
}

// AddHerokuKey associates a Heroku key with the user's API token to allow
// CircleCI to deploy to Heroku on your behalf
//
// The API token being used must be a user API token
//
// NOTE: It doesn't look like there is currently a way to dissaccociate your
// Heroku key, so use with care
func (c *Client) AddHerokuKey(key string) error {
	return c.AddHerokuKeyWithContext(context.Background(), key)
}

// AddHerokuKeyWithContext is the same as AddHerokuKey with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) AddHerokuKeyWithContext(ctx context.Context, key string) error {
	if c.Version < APIVersion11 {
		return newInvalidVersionError(c.Version)
	}
	body := struct {
		APIKey string `json:"apikey"`
	}{APIKey: key}

	return c.request(ctx, "POST", "/user/heroku-key", nil, nil, body)
}

// Pipeline describes a pipeline object.
type Pipeline struct {
	// The unique ID of the pipeline.
	ID string `json:"id"`
	// The current state of the pipeline.
	State string `json:"state"`
	// The number of the pipeline.
	Number int `json:"number"`
	// The date and time the piepeline was created.
	CreatedAt time.Time `json:"created_at"`
}

// TriggerPipeline calls TriggerPipelineWithContext with context.Background.
func (c *Client) TriggerPipeline(vcsType VcsType, account, repo, branch, tag string, params map[string]interface{}) (*Pipeline, error) {
	return c.TriggerPipelineWithContext(context.Background(), vcsType, account, repo, branch, tag, params)
}

// TriggerPipeline triggers a new pipeline for the given project for the given branch or tag.
// Note that branch and tag are mutually exclusive and if both are sent circleci will return
// an error
// https://circleci.com/docs/api/v2/?shell#trigger-a-new-pipeline
// Note that this is only available as a v2 API.
func (c *Client) TriggerPipelineWithContext(ctx context.Context, vcsType VcsType, account, repo, branch, tag string, params map[string]interface{}) (*Pipeline, error) {
	if c.Version < APIVersion2 {
		return nil, newInvalidVersionError(c.Version)
	}

	if branch != "" && tag != "" {
		return nil, errors.New("branch and tag parameters are mutually exclusive. Please send just one")
	}

	p := &Pipeline{}
	body := struct {
		Branch     string                 `json:"branch,omitempty"`
		Tag        string                 `json:"tag,omitempty"`
		Parameters map[string]interface{} `json:"parameters"`
	}{
		Branch:     branch,
		Tag:        tag,
		Parameters: params,
	}

	err := c.request(ctx, http.MethodPost, fmt.Sprintf("project/%s/%s/%s/pipeline", vcsType, account, repo), &p, nil, body)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// GetPipelineByBranch calls GetPipelineByBranchWithContext with context.Background.
func (c *Client) GetPipelineByBranch(vcsType VcsType, account, repo, branch, pageToken string) (*Pipelines, error) {
	return c.GetPipelineByBranchWithContext(context.Background(), vcsType, account, repo, branch, pageToken)
}

// GetPipelineByBranchWithContext gets a pipeline for the given project for the given branch.
// https://circleci.com/docs/api/v2/#operation/listPipelinesForProject
// Note that this is only available as a v2 API.
func (c *Client) GetPipelineByBranchWithContext(ctx context.Context, vcsType VcsType, account, repo, branch, pageToken string) (*Pipelines, error) {
	if c.Version < APIVersion2 {
		return nil, newInvalidVersionError(c.Version)
	}

	if branch == "" {
		return nil, errors.New("branch parameter is required.")
	}

	p := &Pipelines{}
	params := url.Values{}
	if pageToken != "" {
		params.Add("page-token", pageToken)
	}
	params.Add("branch", branch)

	err := c.request(ctx, http.MethodGet, fmt.Sprintf("project/%s/%s/%s/pipeline", vcsType, account, repo), &p, params, nil)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// CancelWorkflow triggers a cancel of the specified workflow using CirclerCI apiV2
// Returns a status message
func (c *Client) CancelWorkflow(workflowID string) (*CancelWorkflow, error) {
	return c.CancelWorkflowWithContext(context.Background(), workflowID)
}

// CancelWorkflowWithContext is the same as CancelWorkflow with the addition of the context
// parameter that would be used to request cancellation.
func (c *Client) CancelWorkflowWithContext(ctx context.Context, workflowID string) (*CancelWorkflow, error) {
	if c.Version < APIVersion2 {
		return nil, newInvalidVersionError(c.Version)
	}
	cancel := &CancelWorkflow{}

	err := c.request(ctx, http.MethodPost, fmt.Sprintf("workflow/%s/cancel", workflowID), cancel, nil, nil)
	if err != nil {
		return nil, err
	}

	return cancel, nil
}

type CancelWorkflow struct {
	Message string `json:"message,omitempty"`
}

type Pipelines struct {
	NextPageToken interface{} `json:"next_page_token,omitempty"`
	Items         []Items     `json:"items"`
}

type Actor struct {
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

type Trigger struct {
	ReceivedAt string `json:"received_at"`
	Type       string `json:"type"`
	Actor      Actor  `json:"actor"`
}

type Vcs struct {
	OriginRepositoryURL string `json:"origin_repository_url"`
	TargetRepositoryURL string `json:"target_repository_url"`
	Revision            string `json:"revision"`
	ProviderName        string `json:"provider_name"`
	Branch              string `json:"branch"`
}

type Items struct {
	ID          string  `json:"id"`
	ProjectSlug string  `json:"project_slug"`
	UpdatedAt   string  `json:"updated_at"`
	Number      int     `json:"number"`
	State       string  `json:"state"`
	CreatedAt   string  `json:"created_at"`
	Trigger     Trigger `json:"trigger"`
	Vcs         Vcs     `json:"vcs"`
}

// WorkflowItem represents a workflow.
type WorkflowItem struct {
	// The ID of the pipeline this workflow belongs to.
	ID string `json:"pipeline_id"`
	// The number of the pipeline this workflow belongs to.
	Number int `json:"pipeline_number"`
	// The current status of the workflow.
	Status string `json:"status"`
	// The unique ID of the workflow.
	WorkflowID string `json:"id"`
	// The name of the workflow.
	Name string `json:"name"`
	// The UUID of the person if it was canceled.
	CanceledBy string `json:"canceled_by"`
	// The UUID of the person if it was errored.
	ErroredBy string `json:"errored_by"`
	// The UUID of the person who started it.
	StartedBy string `json:"started_by"`
	// The project-slug of the pipeline this workflow belongs to.
	ProjectSlug string `json:"project_slug"`
	// The date and time the workflow was created.
	CreatedAt time.Time `json:"created_at"`
	// The date and time the workflow stopped.
	StoppedAt time.Time `json:"stopped_at"`
}

// WorkflowList represents a list of workflow items.
type WorkflowList struct {
	// The list of workflow items.
	Items []WorkflowItem `json:"items"`
	// A token to pass as a page-token query parameter to return the next page of results.
	NextPageToken string `json:"next_page_token"`
}

// GetPipelineWorkflow calls GetPipelineWorkflowWithContext with context.Background.
func (c *Client) GetPipelineWorkflow(pipelineID, pageToken string) (*WorkflowList, error) {
	return c.GetPipelineWorkflowWithContext(context.Background(), pipelineID, pageToken)
}

// GetPipelineWorkflowWithContext returns a list of paginated workflows by pipeline ID
// https://circleci.com/docs/api/v2/?shell#get-a-pipeline-39-s-workflows
// Note that this is only available as a v2 API.
func (c *Client) GetPipelineWorkflowWithContext(ctx context.Context, pipelineID, pageToken string) (*WorkflowList, error) {
	if c.Version < APIVersion2 {
		return nil, newInvalidVersionError(c.Version)
	}
	wf := &WorkflowList{}

	params := url.Values{}
	if pageToken != "" {
		params.Add("page-token", pageToken)
	}
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("pipeline/%s/workflow", pipelineID), &wf, params, nil)
	if err != nil {
		return nil, err
	}

	return wf, nil
}

// EnvVar represents an environment variable
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Artifact represents a build artifact
type Artifact struct {
	NodeIndex  int    `json:"node_index"`
	Path       string `json:"path"`
	PrettyPath string `json:"pretty_path"`
	URL        string `json:"url"`
}

// UserProject returns the selective project information included when querying
// for a User
type UserProject struct {
	Emails      string `json:"emails"`
	OnDashboard bool   `json:"on_dashboard"`
}

// User represents a CircleCI user
type User struct {
	Admin               bool                    `json:"admin"`
	AllEmails           []string                `json:"all_emails"`
	AvatarURL           string                  `json:"avatar_url"`
	BasicEmailPrefs     string                  `json:"basic_email_prefs"`
	Containers          int                     `json:"containers"`
	CreatedAt           time.Time               `json:"created_at"`
	DaysLeftInTrial     int                     `json:"days_left_in_trial"`
	GithubID            int                     `json:"github_id"`
	GithubOauthScopes   []string                `json:"github_oauth_scopes"`
	GravatarID          *string                 `json:"gravatar_id"`
	HerokuAPIKey        *string                 `json:"heroku_api_key"`
	LastViewedChangelog time.Time               `json:"last_viewed_changelog"`
	Login               string                  `json:"login"`
	Name                *string                 `json:"name"`
	Parallelism         int                     `json:"parallelism"`
	Plan                *string                 `json:"plan"`
	Projects            map[string]*UserProject `json:"projects"`
	SelectedEmail       *string                 `json:"selected_email"`
	SignInCount         int                     `json:"sign_in_count"`
	TrialEnd            time.Time               `json:"trial_end"`
}

// AWSConfig represents AWS configuration for a project
type AWSConfig struct {
	AWSKeypair *AWSKeypair `json:"keypair"`
}

// AWSKeypair represents the AWS access/secret key for a project
// SecretAccessKey will be a masked value
type AWSKeypair struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key_id"`
}

// BuildSummary represents the subset of build information returned with a Project
type BuildSummary struct {
	AddedAt     time.Time `json:"added_at"`
	BuildNum    int       `json:"build_num"`
	Outcome     string    `json:"outcome"`
	PushedAt    time.Time `json:"pushed_at"`
	Status      string    `json:"status"`
	VCSRevision string    `json:"vcs_revision"`
}

// Branch represents a repository branch
type Branch struct {
	LastSuccess   *BuildSummary   `json:"last_success"`
	PusherLogins  []string        `json:"pusher_logins"`
	RecentBuilds  []*BuildSummary `json:"recent_builds"`
	RunningBuilds []*BuildSummary `json:"running_builds"`
}

// PublicSSHKey represents the public part of an SSH key associated with a project
// PrivateKey will be a masked value
type PublicSSHKey struct {
	Hostname    string `json:"hostname"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// Project represents information about a project
type Project struct {
	AWSConfig           AWSConfig         `json:"aws"`
	Branches            map[string]Branch `json:"branches"`
	CampfireNotifyPrefs *string           `json:"campfire_notify_prefs"`
	CampfireRoom        *string           `json:"campfire_room"`
	CampfireSubdomain   *string           `json:"campfire_subdomain"`
	CampfireToken       *string           `json:"campfire_token"`
	Compile             string            `json:"compile"`
	DefaultBranch       string            `json:"default_branch"`
	Dependencies        string            `json:"dependencies"`
	Extra               string            `json:"extra"`
	FeatureFlags        FeatureFlags      `json:"feature_flags"`
	FlowdockAPIToken    *string           `json:"flowdock_api_token"`
	Followed            bool              `json:"followed"`
	HallNotifyPrefs     *string           `json:"hall_notify_prefs"`
	HallRoomAPIToken    *string           `json:"hall_room_api_token"`
	HasUsableKey        bool              `json:"has_usable_key"`
	HerokuDeployUser    *string           `json:"heroku_deploy_user"`
	HipchatAPIToken     *string           `json:"hipchat_api_token"`
	HipchatNotify       *bool             `json:"hipchat_notify"`
	HipchatNotifyPrefs  *string           `json:"hipchat_notify_prefs"`
	HipchatRoom         *string           `json:"hipchat_room"`
	IrcChannel          *string           `json:"irc_channel"`
	IrcKeyword          *string           `json:"irc_keyword"`
	IrcNotifyPrefs      *string           `json:"irc_notify_prefs"`
	IrcPassword         *string           `json:"irc_password"`
	IrcServer           *string           `json:"irc_server"`
	IrcUsername         *string           `json:"irc_username"`
	Parallel            int               `json:"parallel"`
	Reponame            string            `json:"reponame"`
	Setup               string            `json:"setup"`
	SlackAPIToken       *string           `json:"slack_api_token"`
	SlackChannel        *string           `json:"slack_channel"`
	SlackNotifyPrefs    *string           `json:"slack_notify_prefs"`
	SlackSubdomain      *string           `json:"slack_subdomain"`
	SlackWebhookURL     *string           `json:"slack_webhook_url"`
	SSHKeys             []*PublicSSHKey   `json:"ssh_keys"`
	Test                string            `json:"test"`
	Username            string            `json:"username"`
	VCSURL              string            `json:"vcs_url"`
}

type FeatureFlags struct {
	TrustyBeta             bool    `json:"trusty-beta"`
	OSX                    bool    `json:"osx"`
	SetGithubStatus        bool    `json:"set-github-status"`
	BuildPRsOnly           bool    `json:"build-prs-only"`
	ForksReceiveSecretVars bool    `json:"forks-receive-secret-env-vars"`
	Fleet                  *string `json:"fleet"`
	BuildForkPRs           bool    `json:"build-fork-prs"`
	AutocancelBuilds       bool    `json:"autocancel-builds"`
	OSS                    bool    `json:"oss"`
	MemoryLimit            *string `json:"memory-limit"`

	raw map[string]interface{}
}

func (f *FeatureFlags) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &f.raw); err != nil {
		return err
	}

	if v, ok := f.raw["trusty-beta"]; ok {
		f.TrustyBeta = v.(bool)
	}

	if v, ok := f.raw["osx"]; ok {
		f.OSX = v.(bool)
	}

	if v, ok := f.raw["set-github-status"]; ok {
		f.SetGithubStatus = v.(bool)
	}

	if v, ok := f.raw["build-prs-only"]; ok {
		f.BuildPRsOnly = v.(bool)
	}

	if v, ok := f.raw["forks-receive-secret-env-vars"]; ok {
		f.ForksReceiveSecretVars = v.(bool)
	}

	if v, ok := f.raw["fleet"]; ok {
		if v != nil {
			s := v.(string)
			f.Fleet = &s
		}
	}

	if v, ok := f.raw["build-fork-prs"]; ok {
		f.BuildForkPRs = v.(bool)
	}

	if v, ok := f.raw["autocancel-builds"]; ok {
		f.AutocancelBuilds = v.(bool)
	}

	if v, ok := f.raw["oss"]; ok {
		f.OSS = v.(bool)
	}

	if v, ok := f.raw["memory-limit"]; ok {
		if v != nil {
			s := v.(string)
			f.MemoryLimit = &s
		}
	}

	return nil
}

// Raw returns the underlying map[string]interface{} representing the feature flags
// This is useful to access flags that have been added to the API, but not yet added to this library
func (f *FeatureFlags) Raw() map[string]interface{} {
	return f.raw
}

// CommitDetails represents information about a commit returned with other
// structs
type CommitDetails struct {
	AuthorDate     *time.Time `json:"author_date"`
	AuthorEmail    string     `json:"author_email"`
	AuthorLogin    string     `json:"author_login"`
	AuthorName     string     `json:"author_name"`
	Body           string     `json:"body"`
	Branch         string     `json:"branch"`
	Commit         string     `json:"commit"`
	CommitURL      string     `json:"commit_url"`
	CommitterDate  *time.Time `json:"committer_date"`
	CommitterEmail string     `json:"committer_email"`
	CommitterLogin string     `json:"committer_login"`
	CommitterName  string     `json:"committer_name"`
	Subject        string     `json:"subject"`
}

// Message represents build messages
type Message struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// Node represents the node a build was run on
type Node struct {
	ImageID      string `json:"image_id"`
	Port         int    `json:"port"`
	PublicIPAddr string `json:"public_ip_addr"`
	SSHEnabled   *bool  `json:"ssh_enabled"`
	Username     string `json:"username"`
}

// CircleYML represents the serialized CircleCI YML file for a given build
type CircleYML struct {
	String string `json:"string"`
}

// BuildStatus represents status information about the build
// Used when a short summary of previous builds is included
type BuildStatus struct {
	BuildTimeMillis int    `json:"build_time_millis"`
	Status          string `json:"status"`
	BuildNum        int    `json:"build_num"`
}

// BuildUser represents the user that triggered the build
type BuildUser struct {
	Email  *string `json:"email"`
	IsUser bool    `json:"is_user"`
	Login  string  `json:"login"`
	Name   *string `json:"name"`
}

// Workflow represents the details of the workflow for a build
type Workflow struct {
	JobName        string    `json:"job_name"`
	JobId          string    `json:"job_id"`
	UpstreamJobIds []*string `json:"upstream_job_ids"`
	WorkflowId     string    `json:"workflow_id"`
	WorkspaceId    string    `json:"workspace_id"`
	WorkflowName   string    `json:"workflow_name"`
}

// Build represents the details of a build
type Build struct {
	AllCommitDetails        []*CommitDetails  `json:"all_commit_details"`
	AuthorDate              *time.Time        `json:"author_date"`
	AuthorEmail             string            `json:"author_email"`
	AuthorName              string            `json:"author_name"`
	Body                    string            `json:"body"`
	Branch                  string            `json:"branch"`
	BuildNum                int               `json:"build_num"`
	BuildParameters         map[string]string `json:"build_parameters"`
	BuildTimeMillis         *int              `json:"build_time_millis"`
	BuildURL                string            `json:"build_url"`
	Canceled                bool              `json:"canceled"`
	CircleYML               *CircleYML        `json:"circle_yml"`
	CommitterDate           *time.Time        `json:"committer_date"`
	CommitterEmail          string            `json:"committer_email"`
	CommitterName           string            `json:"committer_name"`
	Compare                 *string           `json:"compare"`
	DontBuild               *string           `json:"dont_build"`
	Failed                  *bool             `json:"failed"`
	FeatureFlags            map[string]string `json:"feature_flags"`
	InfrastructureFail      bool              `json:"infrastructure_fail"`
	IsFirstGreenBuild       bool              `json:"is_first_green_build"`
	JobName                 *string           `json:"job_name"`
	Lifecycle               string            `json:"lifecycle"`
	Messages                []*Message        `json:"messages"`
	Node                    []*Node           `json:"node"`
	OSS                     bool              `json:"oss"`
	Outcome                 string            `json:"outcome"`
	Parallel                int               `json:"parallel"`
	Picard                  *Picard           `json:"picard"`
	Platform                string            `json:"platform"`
	Previous                *BuildStatus      `json:"previous"`
	PreviousSuccessfulBuild *BuildStatus      `json:"previous_successful_build"`
	PullRequests            []*PullRequest    `json:"pull_requests"`
	QueuedAt                string            `json:"queued_at"`
	Reponame                string            `json:"reponame"`
	Retries                 []int             `json:"retries"`
	RetryOf                 *int              `json:"retry_of"`
	SSHEnabled              *bool             `json:"ssh_enabled"`
	SSHUsers                []*SSHUser        `json:"ssh_users"`
	StartTime               *time.Time        `json:"start_time"`
	Status                  string            `json:"status"`
	Steps                   []*Step           `json:"steps"`
	StopTime                *time.Time        `json:"stop_time"`
	Subject                 string            `json:"subject"`
	Timedout                bool              `json:"timedout"`
	UsageQueuedAt           string            `json:"usage_queued_at"`
	User                    *BuildUser        `json:"user"`
	Username                string            `json:"username"`
	VcsRevision             string            `json:"vcs_revision"`
	VcsTag                  string            `json:"vcs_tag"`
	VCSURL                  string            `json:"vcs_url"`
	Workflows               *Workflow         `json:"workflows"`
	Why                     string            `json:"why"`
}

// Picard represents metadata about an execution environment
type Picard struct {
	BuildAgent    *BuildAgent    `json:"build_agent"`
	ResourceClass *ResourceClass `json:"resource_class"`
	Executor      string         `json:"executor"`
}

// PullRequest represents a pull request
type PullRequest struct {
	HeadSha string `json:"head_sha"`
	URL     string `json:"url"`
}

// ResourceClass represents usable resource information for a job
type ResourceClass struct {
	CPU   float64 `json:"cpu"`
	RAM   int     `json:"ram"`
	Class string  `json:"class"`
}

// BuildAgent represents an agent's information
type BuildAgent struct {
	Image      *string               `json:"image"`
	Properties *BuildAgentProperties `json:"properties"`
}

// BuildAgentProperties represents agent properties
type BuildAgentProperties struct {
	BuildAgent string `json:"image"`
	Executor   string `json:"executor"`
}

// Step represents an individual step in a build
// Will contain more than one action if the step was parallelized
type Step struct {
	Name    string    `json:"name"`
	Actions []*Action `json:"actions"`
}

// Action represents an individual action within a build step
type Action struct {
	Background         bool       `json:"background"`
	BashCommand        *string    `json:"bash_command"`
	Canceled           *bool      `json:"canceled"`
	Continue           *string    `json:"continue"`
	EndTime            *time.Time `json:"end_time"`
	ExitCode           *int       `json:"exit_code"`
	Failed             *bool      `json:"failed"`
	HasOutput          bool       `json:"has_output"`
	Index              int        `json:"index"`
	InfrastructureFail *bool      `json:"infrastructure_fail"`
	Messages           []string   `json:"messages"`
	Name               string     `json:"name"`
	OutputURL          string     `json:"output_url"`
	Parallel           bool       `json:"parallel"`
	RunTimeMillis      int        `json:"run_time_millis"`
	StartTime          *time.Time `json:"start_time"`
	Status             string     `json:"status"`
	Step               int        `json:"step"`
	Timedout           *bool      `json:"timedout"`
	Truncated          bool       `json:"truncated"`
	Type               string     `json:"type"`
}

// TestMetadata represents metadata collected from the test run (e.g. JUnit output)
type TestMetadata struct {
	Classname  string  `json:"classname"`
	File       string  `json:"file"`
	Message    *string `json:"message"`
	Name       string  `json:"name"`
	Result     string  `json:"result"`
	RunTime    float64 `json:"run_time"`
	Source     string  `json:"source"`
	SourceType string  `json:"source_type"`
}

// Output represents the output of a given action
type Output struct {
	Type    string    `json:"type"`
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// SSHUser represents a user associated with an build with SSH enabled
type SSHUser struct {
	GithubID int    `json:"github_id"`
	Login    string `json:"login"`
}

// CheckoutKey represents an SSH checkout key for a project
type CheckoutKey struct {
	PublicKey   string    `json:"public_key"`
	Type        string    `json:"type"` // github-user-key or deploy-key
	Fingerprint string    `json:"fingerprint"`
	Login       *string   `json:"login"` // github username if this is a user key
	Preferred   bool      `json:"preferred"`
	Time        time.Time `json:"time"` // time key was created
}

// VcsType represents the version control system type
type VcsType string

// VcsType constants (github and bitbucket are the currently supported choices)
const (
	VcsTypeGithub    VcsType = "github"
	VcsTypeBitbucket VcsType = "bitbucket"
)

// BuildByProjectResponse is the shape of the response body from the trigger build by project endpoint
type BuildByProjectResponse struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// clean up project returned from API by:
// * url decoding branch names (https://discuss.circleci.com/t/api-returns-url-encoded-branch-names-in-json-response/18524/5)
func cleanupProject(project *Project) error {
	if project.Branches == nil {
		return nil
	}

	newBranches := map[string]Branch{}
	for name, branch := range project.Branches {
		escapedName, err := url.QueryUnescape(name)
		if err != nil {
			return fmt.Errorf("error url decoding branch name '%s':  %s", name, err)
		}

		newBranches[escapedName] = branch
	}
	project.Branches = newBranches

	return nil
}

// GetSummaryMetricsProjects ...
func (c *Client) GetSummaryMetricsProjects(vcsType VcsType, account, repo, branch, pageToken, reportingWindow string, allBranches bool) (*Insigths, error) {
	return c.GetSummaryMetricsProjectsWithContext(context.Background(), vcsType, account, repo, branch, pageToken, reportingWindow, allBranches)
}

// GetSummaryMetricsProjectsWithContext ...
func (c *Client) GetSummaryMetricsProjectsWithContext(ctx context.Context, vcsType VcsType, account, repo, branch, pageToken, reportingWindow string, allBranches bool) (*Insigths, error) {
	if c.Version < APIVersion2 {
		return nil, newInvalidVersionError(c.Version)
	}

	if branch == "" && !allBranches {
		return nil, errors.New("branch parameter is required.")
	}

	i := &Insigths{}
	params := url.Values{}
	if pageToken != "" {
		params.Add("page-token", pageToken)
	}

	if allBranches {
		params.Add("all-branches", "true")
	} else {
		params.Add("branch", branch)
	}

	if reportingWindow != "" {
		params.Add("reporting-window", reportingWindow)
	}

	err := c.request(ctx, http.MethodGet, fmt.Sprintf("insights/%s/%s/%s/workflows", vcsType, account, repo), &i, params, nil)
	if err != nil {
		return nil, err
	}

	return i, nil
}

type Insigths struct {
	NextPageToken string          `json:"next_page_token"`
	Items         []InsigthsItems `json:"items"`
}

type DurationMetrics struct {
	Min               float64 `json:"min"`
	Mean              float64 `json:"mean"`
	Median            float64 `json:"median"`
	P95               float64 `json:"p95"`
	Max               float64 `json:"max"`
	StandardDeviation float64 `json:"standard_deviation"`
}

type Metrics struct {
	TotalRuns        int             `json:"total_runs"`
	SuccessfulRuns   int             `json:"successful_runs"`
	Mttr             float64         `json:"mttr"`
	TotalCreditsUsed int             `json:"total_credits_used"`
	FailedRuns       int             `json:"failed_runs"`
	SuccessRate      float64         `json:"success_rate"`
	TotalRecoveries  int             `json:"total_recoveries"`
	Throughput       float64         `json:"throughput"`
	DurationMetrics  DurationMetrics `json:"duration_metrics"`
}

type InsigthsItems struct {
	Name        string    `json:"name"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Metrics     Metrics   `json:"metrics"`
}
