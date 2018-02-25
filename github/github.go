package github

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/clementine-player/clang-in-the-cloud/format"
	"github.com/dgrijalva/jwt-go"
	"github.com/pmezard/go-difflib/difflib"
	"sourcegraph.com/sourcegraph/go-diff/diff"
)

var (
	privateKey = flag.String("private-key", "", "Path to github app private key")
	hostName   = flag.String("hostname", "clang.clementine-player.org", "Host name for this service")
)

const (
	pullRequestURL       = "https://api.github.com/repos/%s/%s/pulls/%d"
	pullRequestFilesURL  = "https://api.github.com/repos/%s/%s/pulls/%d/files"
	listInstallationsURL = "https://api.github.com/app/installations"
	installationTokenURL = "https://api.github.com/installations/%d/access_tokens"
	createStatusURL      = "https://api.github.com/repos/%s/%s/statuses/%s"
)

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
	Token     string
	ExpiresAt time.Time
}

type Status struct {
	State       string `json:"state"`
	TargetURL   string `json:"target_url"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

func createJWT(keyPath string) (string, error) {
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("Failed to load private key for signing github tokens: %v", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", fmt.Errorf("Failed to parse RSA key from file: %v", err)
	}

	t := time.Now()
	claim := jwt.MapClaims{
		// Issued At Time
		"iat": t.Unix(),
		// Expires at
		"exp": t.Add(time.Minute * 10).Unix(),
		// Unique github app ID
		"iss": 9459,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	ret, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign github token request: %v", err)
	}
	return ret, nil
}

// setAppHeaders adds the necessary authorization headers to access app metadata.
func setAppHeaders(req *http.Request) {
	t, err := createJWT(*privateKey)
	if err != nil {
		log.Fatalf("Failed to sign JWT: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
}

// setInstallHeaders adds the necessary installation-specific authorization headers.
func setInstallHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
}

func getInstallationID(owner string) (int, error) {
	req, _ := http.NewRequest("GET", listInstallationsURL, nil)
	setAppHeaders(req)
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

func createTokenForInstallation(owner string) (string, error) {
	installID, err := getInstallationID(owner)
	if err != nil {
		return "", fmt.Errorf("Failed to get ID for installation: %s %v", owner, err)
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf(installationTokenURL, installID), nil)
	setAppHeaders(req)
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
	return token.Token, nil
}

func getPullRequestSHA(owner string, repo string, number int) (string, error) {
	resp, err := sendRequest("GET", fmt.Sprintf(pullRequestURL, owner, repo, number), owner)
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

func PostSuccessStatus(owner string, repo string, number int) error {
	return postStatus(owner, repo, number, &Status{
		State:       "success",
		TargetURL:   fmt.Sprintf("https://%s/github/%s/%s/%d", *hostName, owner, repo, number),
		Description: "C++ is correctly formatted for this project",
		Context:     "clang-formatter",
	})
}

func PostFailureStatus(owner string, repo string, number int) error {
	return postStatus(owner, repo, number, &Status{
		State:       "failure",
		TargetURL:   fmt.Sprintf("https://%s/github/%s/%s/%d", *hostName, owner, repo, number),
		Description: "C++ is incorrectly formatted for this project",
		Context:     "clang-formatter",
	})
}

func postStatus(owner string, repo string, number int, status *Status) error {
	log.Printf("Posting status for %s/%s/%d: %+v", owner, repo, number, status)
	commit, err := getPullRequestSHA(owner, repo, number)
	if err != nil {
		return fmt.Errorf("Failed to get latest pull request SHA: %v", err)
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf(createStatusURL, owner, repo, commit), nil)
	token, err := createTokenForInstallation(owner)
	if err != nil {
		return fmt.Errorf("Failed to create token: %v", err)
	}
	setInstallHeaders(req, token)
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

func sendRequest(method string, url string, owner string) (*http.Response, error) {
	req, _ := http.NewRequest(method, url, nil)
	token, err := createTokenForInstallation(owner)
	if err != nil {
		return nil, fmt.Errorf("Failed to create token for github request to: %s %v", url, err)
	}
	setInstallHeaders(req, token)
	return http.DefaultClient.Do(req)
}

func CheckPullRequest(owner string, repo string, number int) (string, error) {
	log.Printf("Checking PR %s/%s/%d", owner, repo, number)
	resp, err := sendRequest("GET", fmt.Sprintf(pullRequestFilesURL, owner, repo, number), owner)
	if err != nil {
		log.Printf("Request failed: %+v", err)
		return "", fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Github request status: %d %s", resp.StatusCode, resp.Status)
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Request failed: %s", body)
	}

	dec := json.NewDecoder(resp.Body)
	var listFiles []PullRequestFile
	err = dec.Decode(&listFiles)
	if err != nil {
		log.Printf("Decoding JSON failed: %+v", err)
		return "", fmt.Errorf("Decoding JSON failed: %v", err)
	}

	var diffs []string
	for _, file := range listFiles {
		if !strings.HasSuffix(file.Filename, ".cpp") && !strings.HasSuffix(file.Filename, "*.h") {
			continue
		}
		resp, err := sendRequest("GET", file.RawURL, owner)
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
