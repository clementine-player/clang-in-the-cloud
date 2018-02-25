package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/clementine-player/clang-in-the-cloud/format"
	"github.com/clementine-player/clang-in-the-cloud/github"
	"github.com/gorilla/mux"
)

var (
	address       = flag.String("address", "127.0.0.1", "IP address to listen on")
	port          = flag.Int("port", 10000, "HTTP port to listen on")
	privateKey    = flag.String("private-key", "", "Path to github app private key")
	webhookSecret = flag.String("webhook-secret", "", "")
	verify        = flag.Bool("verify", true, "Whether to verify webhook signatures")
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

func verifyWebhookSignature(signature string, body []byte) error {
	split := strings.Split(signature, "=")
	if len(split) != 2 {
		return fmt.Errorf("Invalid signature: %s", signature)
	}
	if split[0] != "sha1" {
		return fmt.Errorf("Invalid signature type: %s", signature)
	}
	mac, err := hex.DecodeString(split[1])
	if err != nil {
		return fmt.Errorf("Invalid signature hex: %s", signature)
	}

	expected := hmac.New(sha1.New, []byte(*webhookSecret))
	expected.Write(body)
	expectedMac := expected.Sum(nil)
	if !hmac.Equal(mac, expectedMac) {
		return fmt.Errorf("Invalid signature; expected: %s got: %s", split[1], hex.EncodeToString(expectedMac))
	}
	return nil
}

// pushHandler formats a pull request and updates the status when triggered by a webhook.
func (h *githubHandler) pushHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	b, _ := ioutil.ReadAll(r.Body)
	err := verifyWebhookSignature(r.Header.Get("X-Hub-Signature"), b)
	if err != nil {
		log.Printf("Webhook signature verification failed: %v", err)
		if *verify {
			http.Error(w, "Invalid signature for webhook", http.StatusForbidden)
			return
		} else {
			log.Print("Ignoring signature verification failre")
			err = nil
		}
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	var push github.Webhook
	err = dec.Decode(&push)
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

	go h.updatePullRequestStatus(
		push.Repository.Owner.Login, push.Repository.Name, push.Number, push.PullRequest.Head.SHA)
}

func (h *githubHandler) updatePullRequestStatus(owner string, repo string, number int, commit string) error {
	unifiedDiff, err := h.githubClient.CheckPullRequest(owner, repo, number)
	if err != nil {
		return err
	}

	if len(unifiedDiff) == 0 {
		err = h.githubClient.PostSuccessStatus(owner, repo, number, commit)
	} else {
		err = h.githubClient.PostFailureStatus(owner, repo, number, commit)
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
