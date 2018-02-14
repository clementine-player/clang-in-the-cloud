package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

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
	token = flag.String("github", "", "Github personal access token")
)

const (
	pullRequestsURL     = "https://api.github.com/repos/clementine-player/clementine/pulls"
	pullRequestFilesURL = "https://api.github.com/repos/clementine-player/clementine/pulls/%d/files"
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

func githubHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	diff, err := CheckPullRequest(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, diff)
}

func CheckPullRequest(number int) (string, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf(pullRequestFilesURL, number), nil)
	req.Header.Add("Authorization", fmt.Sprintf("token %s", *token))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Request failed: %+v", err)
		return "", fmt.Errorf("Request failed: %v", err)
	}
	defer resp.Body.Close()
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
		r.Header.Add("Authorization", fmt.Sprintf("token %s", *token))
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

func main() {
	flag.Parse()

	r := mux.NewRouter()
	r.HandleFunc("/format", formatHandler)
	r.HandleFunc("/github/{id}", githubHandler)
	log.Print("Starting server...")
	http.Handle("/", r)
	http.ListenAndServe(*address+":"+strconv.Itoa(*port), nil)
}
