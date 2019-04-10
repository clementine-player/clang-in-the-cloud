package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"github.com/clementine-player/clang-in-the-cloud/format"
	"github.com/clementine-player/clang-in-the-cloud/github"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/sourcegraph/go-diff/diff"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	// URL for a commit within a pull request.
	githubCommitURL = "https://github.com/%s/%s/pull/%d/commits/%s"
)

var (
	address          = flag.String("address", "0.0.0.0", "IP address to listen on")
	port             = flag.Int("port", 10000, "HTTP port to listen on")
	privateKey       = flag.String("private-key", "clang-formatter.2019-04-10.private-key.pem.enc", "Path to github app private key")
	webhookSecretEnc = flag.String("webhook-secret", "CiQAAXOmRITJ0LDjJR6b9YsgOluitPZ/KmjsgXbVc6GtiTofebgSVQAFJzUlwRRtSMPf48G1AgAgrIwYbh4w6T7EhB1LPTqN7Wu4Y7Bmiq0S2LZFkS+BfC+KjXmWN+Te9SweCFXRU5JH2V8h4ab0LY0bclYFH39YoNWcnHQ=", "")
	verify           = flag.Bool("verify", true, "Whether to verify webhook signatures")
	hostName         = flag.String("hostname", "clang-in-the-cloud.clementine-player.org", "Host name for this service")

	clientIDEnc     = flag.String("client-id", "CiQAAXOmRO+up3X3QhOg0AOjo0gOMhVaUZ905U+2BB0aILFyarASPQAFJzUlCarqZmsUlGOFQDgpJh9Ju/BcV9gDZ0wkqazRvgvnjgm5XifsUeAwBFq27GLIUMj9uMncNCwjQ0U=", "Github client ID for OAuth")
	clientSecretEnc = flag.String("client-secret", "CiQAAXOmRK3Cm+tDtpYe8iVXKsGKbuyTmn+baVV870B9lbecXBQSUQAFJzUlj/m5uL7mboksjvC8uRHSrpFpH0HtXM32QJSbKMIxi6/79NlNtK+8dnb0XWdCFiPfMce5dV1iLT/Wqt6oF8P/CSQRYmipj1y3JLo/Aw==", "Github client secret for OAuth")
	redirectURL     = flag.String("redirect-url", "http://localhost:10000/github/auth", "Redirect URL for Github OAuth")
	appID           = flag.Int("app-id", 9459, "Github App identifier")
	kmsKey          = flag.String("kms-key", "projects/clementine-data/locations/global/keyRings/clang-in-the-cloud/cryptoKeys/keys", "Path to KMS key for decrypting API keys")
)

var webhookSecret = mustLoadSecret(*webhookSecretEnc)
var clientID = mustLoadSecret(*clientIDEnc)
var clientSecret = mustLoadSecret(*clientSecretEnc)

func mustLoadSecret(enc string) string {
	r, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		log.Fatalf("Failed to base64 decode secret %s: %v", enc, err)
	}
	ctx := context.Background()

	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}
	defer c.Close()

	resp, err := c.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       *kmsKey,
		Ciphertext: r,
	})
	if err != nil {
		log.Fatalf("Failed to decrypt secret: %v", err)
	}
	return string(resp.Plaintext)
}

func mustLoadPrivateKey() *rsa.PrivateKey {
	ctx := context.Background()
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}
	defer c.Close()

	cipher, err := ioutil.ReadFile(*privateKey)
	if err != nil {
		log.Fatalf("Failed to load encrypted private key from %s: %v", *privateKey, err)
	}

	resp, err := c.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       *kmsKey,
		Ciphertext: cipher,
	})
	if err != nil {
		log.Fatalf("Failed to decrypt private key: %v", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(resp.Plaintext)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	return key
}

func formatHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s -- %s", r.Method, r.URL.Path, r.Proto, r.RemoteAddr)
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	out, err := format.FormatFile(r.Body, "foo.cpp")
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
	sessions     *sessions.CookieStore
}

func newGithubHandler() *githubHandler {
	store := sessions.NewCookieStore(securecookie.GenerateRandomKey(64))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 7,
		Domain:   *hostName,
	}
	return &githubHandler{
		githubClient: github.NewAPIClient(*appID, mustLoadPrivateKey()),
		sessions:     store,
	}
}

type PullRequestOutput struct {
	Lines      []Line
	SelfLink   string
	RawLink    string
	GithubLink string
	Owner      string
	OwnerLink  string
	Repo       string
	RepoLink   string
	CommitLink string
	AuthLink   string
	ID         int
	LoggedIn   bool
}

type Line struct {
	Add     bool
	Remove  bool
	Content string
}

type State struct {
	Time     string
	Digest   []byte
	Redirect string
}

// pullRequestHandler formats a pull request and outputs the diff as HTML.
func (h *githubHandler) pullRequestHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	owner := mux.Vars(r)["owner"]
	repo := mux.Vars(r)["repo"]
	diff, err := h.githubClient.CheckPullRequest(owner, repo, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
	err = t.Execute(&buf, PullRequestOutput{
		Lines:    lines,
		SelfLink: fmt.Sprintf("https://%s/github/%s/%s/%d", *hostName, owner, repo, id),
		RawLink:  fmt.Sprintf("https://%s/github/%s/%s/%d.patch", *hostName, owner, repo, id),
		// TODO: Github Enterprise support?
		GithubLink: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, id),
		Owner:      owner,
		OwnerLink:  fmt.Sprintf("https://github.com/%s", owner),
		Repo:       repo,
		RepoLink:   fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		CommitLink: fmt.Sprintf("/github/%s/%s/%d/commit", owner, repo, id),
		ID:         id,
		LoggedIn:   h.isLoggedIn(r),
		AuthLink:   buildAuthRedirect(buildUrl(fmt.Sprintf("/github/%s/%s/%d", owner, repo, id))),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, buf.String())
}

func buildAuthRedirect(redirect string) string {
	u, _ := url.Parse(githubAuthorizeURL)
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", *redirectURL)

	t := time.Now()
	state := State{
		Time:     t.String(),
		Digest:   hmac.New(sha256.New, []byte(clientSecret)).Sum([]byte(t.String())),
		Redirect: redirect,
	}
	s, _ := json.Marshal(state)
	v.Set("state", string(s))
	u.RawQuery = v.Encode()

	return u.String()
}

func buildUrl(path string) string {
	if *hostName == "localhost" {
		return fmt.Sprintf("http://localhost:%d%s", *port, path)
	} else {
		return fmt.Sprintf("https://%s%s", *hostName, path)
	}
}

func (h *githubHandler) rawPullRequestHandler(w http.ResponseWriter, r *http.Request) {
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
	io.WriteString(w, diff)
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

	expected := hmac.New(sha1.New, []byte(webhookSecret))
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
		err = h.githubClient.PostSuccessStatus(*hostName, owner, repo, number, commit)
	} else {
		err = h.githubClient.PostFailureStatus(*hostName, owner, repo, number, commit)
	}
	return err
}

func (h *githubHandler) formatAndCommitPullRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	session, _ := h.sessions.Get(r, "github")
	accessToken := session.Values["access-token"]

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	owner := mux.Vars(r)["owner"]
	repo := mux.Vars(r)["repo"]

	if accessToken == nil {
		u, _ := url.Parse(githubAuthorizeURL)
		v := url.Values{}
		v.Set("client_id", clientID)
		v.Set("redirect_uri", *redirectURL)

		t := time.Now()
		state := State{
			Time:     t.String(),
			Digest:   hmac.New(sha256.New, []byte(clientSecret)).Sum([]byte(t.String())),
			Redirect: buildAuthRedirect(buildUrl(fmt.Sprintf("/github/%s/%s/%d", owner, repo, id))),
		}
		s, _ := json.Marshal(state)
		v.Set("state", string(s))
		u.RawQuery = v.Encode()

		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	// Fetch a list of all files in the PR.
	files, err := h.githubClient.GetFiles(owner, repo, id)
	if err != nil {
		http.Error(w, "Failed to fetch files", http.StatusInternalServerError)
		return
	}

	// 1. Post blobs
	var blobs []*github.TreeFile
	log.Println("Uploading Blobs")
	for _, f := range files {
		contents, err := h.githubClient.FetchRawFile(f.RawURL, owner)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch file contents %s: %v", f.RawURL, err), http.StatusInternalServerError)
			return
		}

		hunks, err := diff.ParseHunks([]byte(f.Patch))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse github's patch: %v", err), http.StatusInternalServerError)
			return
		}

		formatted, err := format.FormatDiff(bytes.NewReader(contents), hunks, f.Filename)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to format file: %v", err), http.StatusInternalServerError)
			return
		}

		sha, err := h.githubClient.UploadBlob(owner, repo, formatted)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to upload blob: %v", err), http.StatusInternalServerError)
			return
		}
		blobs = append(blobs, &github.TreeFile{
			Path: f.Filename,
			Mode: "100644",
			Type: "blob",
			SHA:  sha,
		})
	}

	userClient := github.NewAPIClientFromAccessToken(*appID, accessToken.(string))

	// Get the user we're acting as.
	user, err := userClient.GetUser()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching user info: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("User: %+v", user)

	// Fetch the PR itself
	pr, err := h.githubClient.GetPullRequest(owner, repo, id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching pull request: %v", err), http.StatusInternalServerError)
		return
	}

	baseTree := pr.Head.SHA

	// 2. Create new tree
	treeSHA, err := h.githubClient.CreateTree(owner, repo, blobs, baseTree)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create tree: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("Created new tree: %s", treeSHA)

	// 3. Create commit pointing at tree
	commit, err := h.githubClient.CreateCommit(owner, repo, treeSHA, baseTree, user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create commit: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("Created commit %s from %s to %s", commit, baseTree, treeSHA)

	// 4. Update HEAD
	err = h.githubClient.UpdateReference(owner, repo, pr.Head.Ref, commit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update HEAD: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("Updated head for ref: %s", pr.Head.Ref)

	http.Redirect(w, r, fmt.Sprintf(githubCommitURL, owner, repo, id, commit), http.StatusFound)
}

func (h *githubHandler) authTest(w http.ResponseWriter, r *http.Request) {
	session, _ := h.sessions.Get(r, "github")

	accessToken := session.Values["access-token"]
	if accessToken != nil {
		client := github.NewAPIClientFromAccessToken(*appID, accessToken.(string))
		user, err := client.GetUser()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t := template.Must(template.ParseFiles("user_template.html"))
		err = t.Execute(w, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	u, _ := url.Parse(githubAuthorizeURL)
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", *redirectURL)

	t := time.Now()
	state := State{
		Time:     t.String(),
		Digest:   hmac.New(sha256.New, []byte(clientSecret)).Sum([]byte(t.String())),
		Redirect: buildAuthRedirect(buildUrl("/github/auth-test")),
	}
	s, _ := json.Marshal(state)
	v.Set("state", string(s))
	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *githubHandler) githubAuth(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query()["code"]
	state := r.URL.Query()["state"]

	var s State
	err := json.Unmarshal([]byte(state[0]), &s)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusMethodNotAllowed)
		return
	}

	expected := hmac.New(sha256.New, []byte(clientSecret)).Sum([]byte(s.Time))
	if !hmac.Equal(expected, s.Digest) {
		http.Error(w, "Invalid state digest", http.StatusMethodNotAllowed)
		return
	}

	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("client_secret", clientSecret)
	v.Set("code", code[0])
	v.Set("redirect_uri", *redirectURL)
	v.Set("state", state[0])

	resp, err := http.PostForm(githubTokenURL, v)
	if err != nil {
		http.Error(w, "Failed to authenticate with github", http.StatusForbidden)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	params := extractParams(string(body))
	accessToken := params["access_token"]

	if accessToken == "" {
		log.Printf("Failed to get access token: %v", body)
		http.Error(w, "Failed to get access token for github", http.StatusInternalServerError)
		return
	}

	session, err := h.sessions.Get(r, "github")
	if err != nil {
		log.Printf("Failed to get/decode session: %v", err)
		// Not fatal
	}

	session.Values["access-token"] = accessToken
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Failed to save session: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.Redirect, http.StatusFound)
}

func (h *githubHandler) isLoggedIn(r *http.Request) bool {
	session, err := h.sessions.Get(r, "github")
	if err != nil {
		log.Printf("Failed to get/decode session: %v", err)
	}
	accessToken := session.Values["access-token"]
	if accessToken != nil && accessToken.(string) != "" {
		client := github.NewAPIClientFromAccessToken(*appID, accessToken.(string))
		_, err := client.GetUser()
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
			return false
		}
		return true
	}
	return false
}

func extractParams(body string) map[string]string {
	ret := make(map[string]string)
	params := strings.Split(body, "&")
	for _, param := range params {
		split := strings.Split(param, "=")
		if len(split) == 2 {
			ret[split[0]] = split[1]
		}
	}
	return ret
}

func main() {
	flag.Parse()

	handler := newGithubHandler()

	portEnv := os.Getenv("PORT")
	p, err := strconv.Atoi(portEnv)
	var addr string
	if err == nil && p != 0 {
		addr = *address + ":" + strconv.Itoa(p)
	} else {
		addr = *address + ":" + strconv.Itoa(*port)
	}

	r := mux.NewRouter()
	r.HandleFunc("/format", formatHandler)
	r.HandleFunc("/github/{owner}/{repo}/{id:[0-9]+}", handler.pullRequestHandler)
	r.HandleFunc("/github/{owner}/{repo}/{id:[0-9]+}.patch", handler.rawPullRequestHandler)
	r.HandleFunc("/github/{owner}/{repo}/{id:[0-9]+}/commit", handler.formatAndCommitPullRequest).
		Methods("POST")
	r.HandleFunc("/github/auth-test", handler.authTest)
	r.HandleFunc("/github/auth", handler.githubAuth)
	r.HandleFunc("/github-push", handler.pushHandler)
	r.PathPrefix("/static/").Handler(http.FileServer(http.Dir(".")))
	log.Printf("Starting server on %s ...", addr)
	http.Handle("/", r)
	http.ListenAndServe(addr, nil)
}
