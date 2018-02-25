package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/clementine-player/clang-in-the-cloud/format"
	"github.com/clementine-player/clang-in-the-cloud/github"
	"github.com/gorilla/mux"
)

var (
	address    = flag.String("address", "127.0.0.1", "IP address to listen on")
	port       = flag.Int("port", 10000, "HTTP port to listen on")
	privateKey = flag.String("private-key", "", "Path to github app private key")
)

func formatHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s -- %s", r.Method, r.URL.Path, r.Proto, r.RemoteAddr)
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	out, err := format.FormatFile(r.Body)
	if err != nil {
		log.Printf("clang-format failed: %v", err)
		http.Error(w, "clang-format failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "text/plain")
	w.WriteHeader(200)
	_, err = io.Copy(w, bytes.NewReader(out))
	if err != nil {
		log.Printf("failed to write to response: %v", err)
		return
	}
}

type githubHandler struct {
	githubClient *github.APIClient
}

func newGithubHandler() *githubHandler {
	return &githubHandler{
		githubClient: github.NewAPIClientFromFile(*privateKey),
	}
}

// pullRequestHandler formats a pull request and outputs the diff as HTML.
func (h *githubHandler) pullRequestHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	diff, err := h.githubClient.CheckPullRequest(mux.Vars(r)["owner"], mux.Vars(r)["repo"], id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	html, err := format.FormatAsHTML(diff)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, html)
}

// pushHandler formats a pull request and updates the status when triggered by a webhook.
func (h *githubHandler) pushHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	var push github.Webhook
	err := dec.Decode(&push)
	if err != nil {
		http.Error(w, "Failed to parse webhook", http.StatusInternalServerError)
		return
	}
	log.Printf("Webhook: %+v", push)

	// Ignore anything that is not a pull request event.
	if push.PullRequest == nil {
		return
	}
	if push.Action != "opened" && push.Action != "synchronize" {
		return
	}

	go h.updatePullRequestStatus(push.Repository.Owner.Login, push.Repository.Name, push.Number)
}

func (h *githubHandler) updatePullRequestStatus(owner string, repo string, number int) error {
	unifiedDiff, err := h.githubClient.CheckPullRequest(owner, repo, number)
	if err != nil {
		return err
	}

	if len(unifiedDiff) == 0 {
		err = h.githubClient.PostSuccessStatus(owner, repo, number)
	} else {
		err = h.githubClient.PostFailureStatus(owner, repo, number)
	}
	return err
}

func main() {
	flag.Parse()

	handler := newGithubHandler()

	r := mux.NewRouter()
	r.HandleFunc("/format", formatHandler)
	r.HandleFunc("/github/{owner}/{repo}/{id:[0-9]+}", handler.pullRequestHandler)
	r.HandleFunc("/github-push", handler.pushHandler)
	log.Print("Starting server...")
	http.Handle("/", r)
	http.ListenAndServe(*address+":"+strconv.Itoa(*port), nil)
}
