package github

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/clementine-player/clang-in-the-cloud/format"
	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
	"github.com/pmezard/go-difflib/difflib"
	"sourcegraph.com/sourcegraph/go-diff/diff"
)

const (
	pullRequestURL       = "https://api.github.com/repos/%s/%s/pulls/%d"
	pullRequestFilesURL  = "https://api.github.com/repos/%s/%s/pulls/%d/files"
	listInstallationsURL = "https://api.github.com/app/installations"
	installationTokenURL = "https://api.github.com/installations/%d/access_tokens"
	createStatusURL      = "https://api.github.com/repos/%s/%s/statuses/%s"
	createBlobURL        = "https://api.github.com/repos/%s/%s/git/blobs"
	createTreeURL        = "https://api.github.com/repos/%s/%s/git/trees"
	createCommitURL      = "https://api.github.com/repos/%s/%s/git/commits"
	referenceURL         = "https://api.github.com/repos/%s/%s/git/refs/heads/%s"
	userURL              = "https://api.github.com/user"
)

type webToken struct {
	Signature string
	Expires   time.Time
}

type APIClient struct {
	privateKey  *rsa.PrivateKey
	webToken    *webToken
	tokenCache  *cache.Cache
	accessToken string
}

func NewAPIClient(privateKey *rsa.PrivateKey) *APIClient {
	return &APIClient{
		privateKey: privateKey,
		tokenCache: cache.New(time.Minute, time.Minute),
	}
}

func NewAPIClientFromAccessToken(accessToken string) *APIClient {
	return &APIClient{
		accessToken: accessToken,
	}
}

func NewAPIClientFromFile(keyPath string) *APIClient {
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Failed to load private key for signing github tokens: %v", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalf("Failed to parse RSA key from file: %v", err)
	}
	return NewAPIClient(key)
}

type Webhook struct {
	Action      string
	Number      int
	PullRequest *PullRequest `json:"pull_request"`
	Repository  Repository
}

type PullRequest struct {
	ID       int
	URL      string
	Number   int
	State    string
	Title    string
	Body     string
	Statuses string `json:"statuses_url"`
	Head     Head
}

type Head struct {
	SHA string `json:"sha"`
	Ref string `json:"ref"`
}

type Repository struct {
	ID       int
	Name     string
	FullName string
	Owner    Account
}

type PullRequestFile struct {
	SHA      string
	Filename string
	BlobURL  string `json:"blob_url"`
	RawURL   string `json:"raw_url"`
	Patch    string
}

type Installation struct {
	ID      int     `json:"id"`
	Account Account `json:"account"`
}

type Account struct {
	Login string `json:"login"`
}

type InstallationToken struct {
	Token   string
	Expires time.Time `json:"expires_at"`
}

type Status struct {
	State       string `json:"state"`
	TargetURL   string `json:"target_url"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

type Blob struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type CreateBlobResponse struct {
	URL string
	SHA string
}

type TreeFile struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type CreateTree struct {
	BaseTree string      `json:"base_tree"`
	Tree     []*TreeFile `json:"tree"`
}

type CreateTreeResponse struct {
	SHA  string
	URL  string
	Tree []*TreeFile
}

type Author struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
}

type CreateCommit struct {
	Message   string   `json:"message"`
	Parents   []string `json:"parents"`
	Tree      string   `json:"tree"`
	Author    Author   `json:"author"`
	Committer Author   `json:"committer"`
}

type CreateCommitResponse struct {
	SHA string
	URL string
}

type UpdateReference struct {
	SHA   string `json:"sha"`
	Force bool   `json:"force"`
}

type UpdateReferenceResponse struct {
	Ref string
	URL string
}

type Object struct {
	Type string
	SHA  string
	URL  string
}

type Reference struct {
	Ref    string
	URL    string
	Object Object
}

type User struct {
	Login     string
	URL       string
	Name      string
	Email     string
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

func (c *APIClient) createJWT() (string, error) {
	t := time.Now()
	if c.webToken != nil && c.webToken.Expires.Sub(t) > time.Minute {
		return c.webToken.Signature, nil
	}

	expires := t.Add(time.Minute * 10)
	claim := jwt.MapClaims{
		// Issued At Time
		"iat": t.Unix(),
		// Expires at
		"exp": expires.Unix(),
		// Unique github app ID
		"iss": 9459,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	ret, err := token.SignedString(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign github token request: %v", err)
	}
	c.webToken = &webToken{
		Signature: ret,
		Expires:   expires,
	}
	return ret, nil
}

// setAppHeaders adds the necessary authorization headers to access app metadata.
func (c *APIClient) setAppHeaders(req *http.Request) {
	t, err := c.createJWT()
	if err != nil {
		log.Fatalf("Failed to sign JWT: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
}

// setTokenHeaders adds the necessary installation-specific authorization headers.
func (c *APIClient) setTokenHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
}

func (c *APIClient) getInstallationID(owner string) (int, error) {
	req, _ := http.NewRequest("GET", listInstallationsURL, nil)
	c.setAppHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, fmt.Errorf("Failed to list app installations: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := ioutil.ReadAll(resp.Body)
		return -1, fmt.Errorf("Failed to list app installations: %s %s", resp.Status, b)
	}

	dec := json.NewDecoder(resp.Body)
	var installs []Installation
	err = dec.Decode(&installs)
	if err != nil {
		log.Printf("Decoding JSON failed: %+v", err)
		return -1, fmt.Errorf("Decoding JSON failed: %v", err)
	}

	for _, install := range installs {
		if install.Account.Login == owner {
			return install.ID, nil
		}
	}
	return -1, fmt.Errorf("No permissions for owner: %s", owner)
}

func (c *APIClient) actingAsUser() bool {
	return c.accessToken != ""
}

func (c *APIClient) actingAsApp() bool {
	return !c.actingAsUser()
}

func (c *APIClient) getToken(owner string) (string, error) {
	if c.accessToken != "" {
		return c.accessToken, nil
	} else if owner == "" {
		return "", fmt.Errorf("Owner must be specified when acting as an app")
	} else {
		return c.createTokenForInstallation(owner)
	}
}

func (c *APIClient) createTokenForInstallation(owner string) (string, error) {
	v, ok := c.tokenCache.Get(owner)
	if ok {
		token, _ := v.(InstallationToken)
		return token.Token, nil
	}

	installID, err := c.getInstallationID(owner)
	if err != nil {
		return "", fmt.Errorf("Failed to get ID for installation: %s %v", owner, err)
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf(installationTokenURL, installID), nil)
	c.setAppHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to get installation token: %v", err)
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var token InstallationToken
	err = dec.Decode(&token)
	if err != nil {
		return "", fmt.Errorf("Decoding JSON failed: %v", err)
	}
	log.Printf("New installation token for: %s %+v", owner, token)

	c.tokenCache.Set(owner, token, token.Expires.Sub(time.Now())-time.Minute)

	return token.Token, nil
}

func (c *APIClient) sendRequest(method string, url string, owner string) (*http.Response, error) {
	req, _ := http.NewRequest(method, url, nil)
	token, err := c.getToken(owner)
	if err != nil {
		return nil, fmt.Errorf("Failed to create token for github request to: %s %v", url, err)
	}
	c.setTokenHeaders(req, token)
	return http.DefaultClient.Do(req)
}

func (c *APIClient) get(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	token, err := c.getToken("")
	if err != nil {
		return nil, fmt.Errorf("Failed to create token for github request to: %s %v", url, err)
	}
	c.setTokenHeaders(req, token)
	return http.DefaultClient.Do(req)
}

func (c *APIClient) post(url string, owner string, body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest("POST", url, body)
	token, err := c.getToken(owner)
	if err != nil {
		return nil, fmt.Errorf("Failed to create token for github request to: %s %v", url, err)
	}
	c.setTokenHeaders(req, token)
	return http.DefaultClient.Do(req)
}

func (c *APIClient) patch(url string, owner string, body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest("PATCH", url, body)
	token, err := c.getToken(owner)
	if err != nil {
		return nil, fmt.Errorf("Failed to create token for github request to: %s %v", url, err)
	}
	c.setTokenHeaders(req, token)
	return http.DefaultClient.Do(req)
}

func (c *APIClient) getPullRequestSHA(owner string, repo string, number int) (string, error) {
	resp, err := c.sendRequest("GET", fmt.Sprintf(pullRequestURL, owner, repo, number), owner)
	if err != nil {
		return "", fmt.Errorf("Failed to fetch pull request details: %v", err)
	}
	defer resp.Body.Close()

	var pr PullRequest
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&pr)
	if err != nil {
		return "", fmt.Errorf("Failed to decode JSON: %v", err)
	}
	return pr.Head.SHA, nil
}

func (c *APIClient) PostSuccessStatus(hostName string, owner string, repo string, number int, commit string) error {
	return c.postStatus(owner, repo, commit, &Status{
		State:       "success",
		TargetURL:   fmt.Sprintf("https://%s/github/%s/%s/%d", hostName, owner, repo, number),
		Description: "C++ is correctly formatted for this project",
		Context:     "clang-formatter",
	})
}

func (c *APIClient) PostFailureStatus(hostName string, owner string, repo string, number int, commit string) error {
	return c.postStatus(owner, repo, commit, &Status{
		State:       "failure",
		TargetURL:   fmt.Sprintf("https://%s/github/%s/%s/%d", hostName, owner, repo, number),
		Description: "C++ is incorrectly formatted for this project",
		Context:     "clang-formatter",
	})
}

func (c *APIClient) postStatus(owner string, repo string, commit string, status *Status) error {
	req, _ := http.NewRequest("POST", fmt.Sprintf(createStatusURL, owner, repo, commit), nil)
	token, err := c.createTokenForInstallation(owner)
	if err != nil {
		return fmt.Errorf("Failed to create token: %v", err)
	}
	c.setTokenHeaders(req, token)
	data, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %v", err)
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to post status: %v", err)
	}
	defer resp.Body.Close()
	return nil
}

func (c *APIClient) CheckPullRequest(owner string, repo string, number int) (string, error) {
	log.Printf("Checking PR %s/%s/%d", owner, repo, number)
	listFiles, err := c.GetFiles(owner, repo, number)
	if err != nil {
		return "", fmt.Errorf("Failed to fetch files: %v", err)
	}

	var diffs []string
	for _, file := range listFiles {
		if !strings.HasSuffix(file.Filename, ".cpp") && !strings.HasSuffix(file.Filename, ".h") {
			continue
		}
		resp, err := c.sendRequest("GET", file.RawURL, owner)
		if err != nil {
			log.Printf("Request failed: %+v", err)
			continue
		}

		hunks, err := diff.ParseHunks([]byte(file.Patch))
		if err != nil {
			log.Printf("Failed to parse patch: %v", err)
			continue
		}

		defer resp.Body.Close()
		original, _ := ioutil.ReadAll(resp.Body)
		formatted, err := format.Format(bytes.NewReader(original), hunks)
		if err != nil {
			log.Printf("Failed to format file: %s", file.Filename)
			continue
		}
		if !bytes.Equal(original, formatted) {
			log.Printf("File not formatted correctly: %s", file.Filename)
			diff := difflib.UnifiedDiff{
				A:        difflib.SplitLines(string(original)),
				B:        difflib.SplitLines(string(formatted)),
				FromFile: fmt.Sprintf("%s.orig", file.Filename),
				ToFile:   file.Filename,
				Context:  3,
			}
			text, _ := difflib.GetUnifiedDiffString(diff)
			diffs = append(diffs, text)
		}
	}

	var fileDiffs []*diff.FileDiff
	for _, d := range diffs {
		fileDiff, _ := diff.ParseFileDiff([]byte(d))
		fileDiffs = append(fileDiffs, fileDiff)
	}
	unifiedDiff, err := diff.PrintMultiFileDiff(fileDiffs)
	if err != nil {
		log.Printf("Failed to print unified diff: %v", err)
		return "", fmt.Errorf("Failed to print unified diff: %v", err)
	}
	return string(unifiedDiff), nil
}

func (c *APIClient) GetFiles(owner string, repo string, number int) ([]PullRequestFile, error) {
	log.Printf("Fetching file list for PR %s/%s/%d", owner, repo, number)
	resp, err := c.sendRequest("GET", fmt.Sprintf(pullRequestFilesURL, owner, repo, number), owner)
	if err != nil {
		log.Printf("Request failed: %+v", err)
		return nil, fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Github request status: %d %s", resp.StatusCode, resp.Status)
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Request failed: %s", body)
	}

	dec := json.NewDecoder(resp.Body)
	var listFiles []PullRequestFile
	err = dec.Decode(&listFiles)
	if err != nil {
		log.Printf("Decoding JSON failed: %+v", err)
		return nil, fmt.Errorf("Decoding JSON failed: %v", err)
	}
	return listFiles, nil
}

func (c *APIClient) FetchRawFile(url string, owner string) ([]byte, error) {
	resp, err := c.sendRequest("GET", url, owner)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch file %s: %v", url, err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch file %s: %v", url, err)
	}
	return data, nil
}

func (c *APIClient) UploadBlob(owner string, repo string, content []byte) (string, error) {
	req := &Blob{
		Content:  base64.StdEncoding.EncodeToString(content),
		Encoding: "base64",
	}
	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal blob request: %v", err)
	}
	resp, err := c.post(fmt.Sprintf(createBlobURL, owner, repo), owner, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("Request failed: %v", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Request failed: %s", body)
	}

	dec := json.NewDecoder(resp.Body)
	var blob CreateBlobResponse
	err = dec.Decode(&blob)
	if err != nil {
		return "", fmt.Errorf("Decoding JSON failed: %v", err)
	}
	return blob.SHA, nil
}

func (c *APIClient) CreateTree(owner string, repo string, blobs []*TreeFile, base string) (string, error) {
	req := &CreateTree{
		BaseTree: base,
		Tree:     blobs,
	}
	data, _ := json.Marshal(req)
	resp, err := c.post(fmt.Sprintf(createTreeURL, owner, repo), owner, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Request failed: %s", body)
	}

	dec := json.NewDecoder(resp.Body)
	var tree CreateTreeResponse
	err = dec.Decode(&tree)
	if err != nil {
		return "", fmt.Errorf("Decoding json failed: %v", err)
	}

	return tree.SHA, nil
}

func (c *APIClient) CreateCommit(owner string, repo string, tree string, baseTree string) (string, error) {
	t := time.Now()
	req := &CreateCommit{
		Message: "Automatically formatted",
		Parents: []string{baseTree},
		Tree:    tree,
		Author: Author{
			Name:  "Clang Formatter",
			Email: "clang@clementine-player.org",
			Date:  t,
		},
		Committer: Author{
			Name:  "Clang Formatter",
			Email: "clang@clementine-player.org",
			Date:  t,
		},
	}
	data, _ := json.Marshal(req)
	resp, err := c.post(fmt.Sprintf(createCommitURL, owner, repo), owner, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Request failed: %s", body)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("Created commit: %s", body)

	dec := json.NewDecoder(bytes.NewReader(body))
	var commit CreateCommitResponse
	err = dec.Decode(&commit)
	if err != nil {
		return "", fmt.Errorf("Decoding json failed: %v", err)
	}
	return commit.SHA, nil
}

func (c *APIClient) UpdateReference(owner string, repo string, ref string, sha string) error {
	req := &UpdateReference{
		SHA: sha,
		// Never overwrite other work.
		Force: false,
	}
	log.Printf("Updating ref %s with %+v", ref, req)
	data, _ := json.Marshal(req)
	resp, err := c.patch(fmt.Sprintf(referenceURL, owner, repo, ref), owner, bytes.NewReader(data))

	if err != nil {
		return fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Request failed: %s", body)
	}

	dec := json.NewDecoder(resp.Body)
	var update UpdateReferenceResponse
	err = dec.Decode(&update)
	if err != nil {
		return fmt.Errorf("Decoding json failed: %v", err)
	}
	return nil
}

func (c *APIClient) GetPullRequest(owner string, repo string, number int) (*PullRequest, error) {
	resp, err := c.sendRequest("GET", fmt.Sprintf(pullRequestURL, owner, repo, number), owner)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch pull request details: %v", err)
	}
	defer resp.Body.Close()

	var pr PullRequest
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&pr)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode JSON: %v", err)
	}
	return &pr, nil
}

func (c *APIClient) GetUser() (*User, error) {
	if !c.actingAsUser() {
		return nil, fmt.Errorf("Cannot fetch user info when not acting as a user")
	}

	resp, err := c.get(userURL)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch user information")
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var user User
	err = dec.Decode(&user)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode JSON: %v", err)
	}
	return &user, nil
}
