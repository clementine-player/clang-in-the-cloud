package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/pmezard/go-difflib/difflib"
	"sourcegraph.com/sourcegraph/go-diff/diff"
)

var (
	address      = flag.String("address", "127.0.0.1", "IP address to listen on")
	port         = flag.Int("port", 10000, "HTTP port to listen on")
	clang_format = flag.String("clang-format", "clang-format",
		"Path to the clang-format executable to use")
	style = flag.String("style",
		"{BasedOnStyle: Google, DerivePointerBinding: false, Standard: Cpp11}",
		"Style specification passed to clang-format")
	token      = flag.String("github", "", "Github personal access token")
	privateKey = flag.String("private-key", "", "Path to github app private key")
)

const (
	pullRequestsURL      = "https://api.github.com/repos/%s/%s/pulls"
	pullRequestFilesURL  = "https://api.github.com/repos/%s/%s/pulls/%d/files"
	listInstallationsURL = "https://api.github.com/app/installations"
	installationTokenURL = "https://api.github.com/installations/%d/access_tokens"
)

type PullRequest struct {
	ID       int
	URL      string
	Number   int
	State    string
	Title    string
	Body     string
	Statuses string `json:"statuses_url"`
}

type PullRequestFile struct {
	SHA      string `json:"sha"`
	Filename string `json:"filename"`
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
		"iat": t.Unix(),
		"exp": t.Add(time.Minute * 10).Unix(),
		"iss": 9459,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	ret, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign github token request: %v", err)
	}
	log.Printf("JWT: %s", ret)
	return ret, nil
}

func getInstallationID(owner string) (int, error) {
	req, _ := http.NewRequest("GET", listInstallationsURL, nil)
	t, err := createJWT(*privateKey)
	if err != nil {
		return -1, fmt.Errorf("failed to create JWT: %v", err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
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
	log.Printf("Installations: %v", installs)
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
	t, err := createJWT(*privateKey)
	if err != nil {
		return "", fmt.Errorf("Failed to create JWT: %v", err)
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf(installationTokenURL, installID), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
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

func format(r io.Reader, hunks []*diff.Hunk) ([]byte, error) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	args := []string{"-style", *style}
	for _, hunk := range hunks {
		args = append(args, "-lines")
		args = append(args, fmt.Sprintf("%d:%d", hunk.NewStartLine, hunk.NewStartLine+hunk.NewLines))
	}
	log.Printf("Args: %v", args)

	cmd := exec.Command(*clang_format, args...)
	cmd.Stdin = r
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("clang-format failed: %v", err)
		return nil, fmt.Errorf("clang-format: %s", stderr.String())
	}
	return stdout.Bytes(), nil
}

func formatHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s -- %s", r.Method, r.URL.Path, r.Proto, r.RemoteAddr)
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	cmd := exec.Command(*clang_format, "-style", *style)
	cmd.Stdin = r.Body
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("clang-format failed: %v", err)
		if stderr.String() != "" {
			log.Printf("stderr: %s", stderr.String())
		}
		w.WriteHeader(500)
		return
	}

	w.Header().Set("content-type", "text/plain")
	w.WriteHeader(200)
	_, err = io.Copy(w, bytes.NewReader(stdout.Bytes()))
	if err != nil {
		log.Printf("failed to write to response: %v", err)
		return
	}
}

func githubClementineHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	diff, err := CheckPullRequest("clementine-player", "clementine", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, diff)
}

func githubHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	diff, err := CheckPullRequest(mux.Vars(r)["owner"], mux.Vars(r)["repo"], id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	html, err := formatAsHTML(diff)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, html)
}

func CheckPullRequest(owner string, repo string, number int) (string, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf(pullRequestFilesURL, owner, repo, number), nil)
	token, err := createTokenForInstallation(owner)
	if err != nil {
		return "", fmt.Errorf("Failed to create token for github request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	log.Printf("Auth: %s", req.Header.Get("Authorization"))
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
	resp, err := http.DefaultClient.Do(req)
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
		r, _ := http.NewRequest("GET", file.RawURL, nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		r.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
		resp, err := http.DefaultClient.Do(r)
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
		formatted, err := format(bytes.NewReader(original), hunks)
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

type Diff struct {
	Lines []Line
}

type Line struct {
	Add     bool
	Remove  bool
	Content string
}

func formatAsHTML(diff string) (string, error) {
	t := template.Must(template.ParseFiles("diff_template.html"))
	var lines []Line
	for _, line := range strings.Split(diff, "\n") {
		lines = append(lines, Line{
			Add:     strings.HasPrefix(line, "+"),
			Remove:  strings.HasPrefix(line, "-"),
			Content: line,
		})
	}
	buf := bytes.Buffer{}
	err := t.Execute(&buf, Diff{Lines: lines})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func main() {
	flag.Parse()

	r := mux.NewRouter()
	r.HandleFunc("/format", formatHandler)
	r.HandleFunc("/github/{id}", githubClementineHandler)
	r.HandleFunc("/github/{owner}/{repo}/{id}", githubHandler)
	log.Print("Starting server...")
	http.Handle("/", r)
	http.ListenAndServe(*address+":"+strconv.Itoa(*port), nil)
}
