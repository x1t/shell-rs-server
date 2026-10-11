package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct horse battery"

// fixture is a server on a fresh database file with one user, "me".
type fixture struct {
	t      *testing.T
	store  *Store
	server *Server
	http   *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store, err := openStore(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	run := func(args ...string) {
		if err := setPassword(store, args[0], args[1], func() (string, error) { return testPassword, nil }, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "me")
	server, err := newServer(store, false)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.routes())
	t.Cleanup(httpServer.Close)
	return &fixture{t: t, store: store, server: server, http: httpServer}
}

// call sends body as JSON and decodes the answer into out, returning the
// status.
func (f *fixture) call(method, path, token string, body, out any) int {
	f.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.http.URL+path, reader)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			f.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// login runs what a client runs: prelogin, the KDF, login.
func (f *fixture) login(username, password string) (int, loginResponse) {
	f.t.Helper()
	var params kdfParams
	if status := f.call("POST", "/api/prelogin", "", usernameRequest{username}, &params); status != http.StatusOK {
		f.t.Fatalf("prelogin: %d", status)
	}
	var resp loginResponse
	status := f.call("POST", "/api/login", "", loginRequest{username, authKey(password, params.Salt), "test"}, &resp)
	return status, resp
}

func (f *fixture) token() string {
	f.t.Helper()
	status, resp := f.login("me", testPassword)
	if status != http.StatusOK {
		f.t.Fatalf("login: %d", status)
	}
	return resp.Token
}

func (f *fixture) push(token string, pushes ...Push) PushResult {
	f.t.Helper()
	var result PushResult
	if status := f.call("POST", "/api/records", token, pushRequest{pushes}, &result); status != http.StatusOK {
		f.t.Fatalf("push: %d", status)
	}
	return result
}

func (f *fixture) pull(token string, since int64) pullResponse {
	f.t.Helper()
	var resp pullResponse
	if status := f.call("GET", fmt.Sprintf("/api/records?since=%d", since), token, nil, &resp); status != http.StatusOK {
		f.t.Fatalf("pull: %d", status)
	}
	return resp
}

func TestPreloginDoesNotTellWhoHasAnAccount(t *testing.T) {
	f := newFixture(t)
	var known, unknown, again kdfParams
	f.call("POST", "/api/prelogin", "", usernameRequest{"me"}, &known)
	f.call("POST", "/api/prelogin", "", usernameRequest{"nobody"}, &unknown)
	f.call("POST", "/api/prelogin", "", usernameRequest{"nobody"}, &again)

	u, _ := f.store.user("me")
	if !bytes.Equal(known.Salt, u.KdfSalt) {
		t.Error("a user gets their own salt")
	}
	if len(unknown.Salt) != saltSize || !bytes.Equal(unknown.Salt, again.Salt) {
		t.Error("a name without an account gets a salt, the same each time")
	}
	if unknown.Time != kdfTime || unknown.Memory != kdfMemory || unknown.Threads != kdfThreads {
		t.Errorf("parameters: %+v", unknown)
	}
}

func TestLoginTakesOnlyTheRightPassword(t *testing.T) {
	f := newFixture(t)
	if status, _ := f.login("me", "wrong password"); status != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", status)
	}
	if status, _ := f.login("nobody", testPassword); status != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", status)
	}
	status, resp := f.login("me", testPassword)
	if status != http.StatusOK || resp.Token == "" || resp.VaultKey != nil {
		t.Errorf("right password: %d %+v", status, resp)
	}
}

func TestTooManyFailedLoginsAreTurnedAway(t *testing.T) {
	f := newFixture(t)
	for range 10 {
		f.login("me", "wrong password")
	}
	// Even the right password, until the window passes.
	if status, _ := f.login("me", testPassword); status != http.StatusTooManyRequests {
		t.Errorf("after ten failures: %d", status)
	}
	f.server.logins.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if status, _ := f.login("me", testPassword); status != http.StatusOK {
		t.Errorf("after the window: %d", status)
	}
}

func TestRecordsNeedALiveSession(t *testing.T) {
	f := newFixture(t)
	if status := f.call("GET", "/api/records?since=0", "", nil, nil); status != http.StatusUnauthorized {
		t.Errorf("no token: %d", status)
	}
	if status := f.call("GET", "/api/records?since=0", "made-up", nil, nil); status != http.StatusUnauthorized {
		t.Errorf("made-up token: %d", status)
	}
	token := f.token()
	if status := f.call("POST", "/api/logout", token, nil, nil); status != http.StatusNoContent {
		t.Errorf("logout: %d", status)
	}
	if status := f.call("GET", "/api/records?since=0", token, nil, nil); status != http.StatusUnauthorized {
		t.Errorf("after logout: %d", status)
	}
}

func TestTheFirstDevicesVaultKeyIsTheOneKept(t *testing.T) {
	f := newFixture(t)
	first, second := f.token(), f.token()
	if status := f.call("PUT", "/api/vault-key", first, vaultKeyBody{[]byte("first")}, nil); status != http.StatusNoContent {
		t.Fatalf("first: %d", status)
	}
	var kept vaultKeyBody
	if status := f.call("PUT", "/api/vault-key", second, vaultKeyBody{[]byte("second")}, &kept); status != http.StatusConflict {
		t.Errorf("second: %d", status)
	}
	if string(kept.VaultKey) != "first" {
		t.Errorf("conflict answers with the kept key, got %q", kept.VaultKey)
	}
	if _, resp := f.login("me", testPassword); string(resp.VaultKey) != "first" {
		t.Errorf("login hands out the key, got %q", resp.VaultKey)
	}
}

func TestPushedRecordsComeBackInRevisionOrder(t *testing.T) {
	f := newFixture(t)
	token := f.token()
	result := f.push(token, Push{ID: "a", Data: []byte("1")}, Push{ID: "b", Data: []byte("2")})
	if len(result.Applied) != 2 || result.Revision != 2 || len(result.Conflicts) != 0 {
		t.Fatalf("push: %+v", result)
	}
	f.push(token, Push{ID: "a", BaseRevision: 1, Data: []byte("1b")})

	all := f.pull(token, 0)
	if all.Revision != 3 || all.More || len(all.Records) != 2 {
		t.Fatalf("pull: %+v", all)
	}
	if all.Records[0].ID != "b" || all.Records[1].ID != "a" || string(all.Records[1].Data) != "1b" {
		t.Errorf("order and content: %+v", all.Records)
	}
	if since := f.pull(token, 2); len(since.Records) != 1 || since.Records[0].Revision != 3 {
		t.Errorf("since 2: %+v", since)
	}
}

func TestAStaleChangeComesBackAsAConflict(t *testing.T) {
	f := newFixture(t)
	token := f.token()
	f.push(token, Push{ID: "a", Data: []byte("one")})
	f.push(token, Push{ID: "a", BaseRevision: 1, Data: []byte("two")})

	// A device that saw only revision 1, and one that never saw it.
	result := f.push(token,
		Push{ID: "a", BaseRevision: 1, Data: []byte("stale")},
		Push{ID: "a2", Data: []byte("fresh")})
	if len(result.Conflicts) != 1 || string(result.Conflicts[0].Data) != "two" || result.Conflicts[0].Revision != 2 {
		t.Errorf("conflict: %+v", result.Conflicts)
	}
	if len(result.Applied) != 1 || result.Applied[0].ID != "a2" {
		t.Errorf("the rest still goes in: %+v", result.Applied)
	}
	created := f.push(token, Push{ID: "a", Data: []byte("made again")})
	if len(created.Conflicts) != 1 {
		t.Errorf("a record made on two devices with one id conflicts: %+v", created)
	}
}

func TestDeletedRecordsStayAsTombstones(t *testing.T) {
	f := newFixture(t)
	token := f.token()
	f.push(token, Push{ID: "a", Data: []byte("secret")})
	f.push(token, Push{ID: "a", BaseRevision: 1, Deleted: true})

	pulled := f.pull(token, 0)
	if len(pulled.Records) != 1 || !pulled.Records[0].Deleted || len(pulled.Records[0].Data) != 0 {
		t.Errorf("tombstone: %+v", pulled.Records)
	}

	// On the wire, an empty string: clients need not take null for bytes.
	req, _ := http.NewRequest("GET", f.http.URL+"/api/records?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw bytes.Buffer
	raw.ReadFrom(resp.Body)
	if !strings.Contains(raw.String(), `"data":""`) {
		t.Errorf("tombstone on the wire: %s", raw.String())
	}
}

func TestALongHistoryComesInPages(t *testing.T) {
	f := newFixture(t)
	token := f.token()
	pushes := make([]Push, 0, pageSize+5)
	for i := range pageSize + 5 {
		pushes = append(pushes, Push{ID: fmt.Sprintf("r%d", i), Data: []byte("x")})
	}
	f.push(token, pushes...)

	first := f.pull(token, 0)
	if !first.More || len(first.Records) != pageSize {
		t.Fatalf("first page: more=%v len=%d", first.More, len(first.Records))
	}
	rest := f.pull(token, first.Records[pageSize-1].Revision)
	if rest.More || len(rest.Records) != 5 {
		t.Errorf("second page: more=%v len=%d", rest.More, len(rest.Records))
	}
}

func TestMalformedPushesAreRefused(t *testing.T) {
	f := newFixture(t)
	token := f.token()
	cases := map[string][]Push{
		"empty id":     {{ID: "", Data: []byte("x")}},
		"bad id":       {{ID: "a/b", Data: []byte("x")}},
		"long id":      {{ID: strings.Repeat("a", maxRecordID+1), Data: []byte("x")}},
		"twice":        {{ID: "a", Data: []byte("x")}, {ID: "a", Data: []byte("y")}},
		"no data":      {{ID: "a"}},
		"negative rev": {{ID: "a", BaseRevision: -1, Data: []byte("x")}},
	}
	for name, pushes := range cases {
		if status := f.call("POST", "/api/records", token, pushRequest{pushes}, nil); status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, status)
		}
	}
	if status := f.call("GET", "/api/records?since=-1", token, nil, nil); status != http.StatusBadRequest {
		t.Errorf("negative since: %d", status)
	}
}

func TestUsersSeeOnlyTheirOwnRecords(t *testing.T) {
	f := newFixture(t)
	if err := setPassword(f.store, "add", "other", func() (string, error) { return testPassword, nil }, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	f.push(f.token(), Push{ID: "a", Data: []byte("mine")})
	_, other := f.login("other", testPassword)
	if pulled := f.pull(other.Token, 0); len(pulled.Records) != 0 {
		t.Errorf("other user sees: %+v", pulled.Records)
	}
	// The same id is theirs to use.
	if result := f.push(other.Token, Push{ID: "a", Data: []byte("theirs")}); len(result.Conflicts) != 0 {
		t.Errorf("other user's push: %+v", result)
	}
}

func TestANewPasswordClearsWhatWasSealedWithTheOld(t *testing.T) {
	f := newFixture(t)
	token := f.token()
	f.call("PUT", "/api/vault-key", token, vaultKeyBody{[]byte("key")}, nil)
	f.push(token, Push{ID: "a", Data: []byte("x")})

	newPassword := func() (string, error) { return "another password", nil }
	if err := setPassword(f.store, "passwd", "me", newPassword, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if status := f.call("GET", "/api/records?since=0", token, nil, nil); status != http.StatusUnauthorized {
		t.Errorf("old session: %d", status)
	}
	if status, _ := f.login("me", testPassword); status != http.StatusUnauthorized {
		t.Errorf("old password: %d", status)
	}
	status, resp := f.login("me", "another password")
	if status != http.StatusOK || resp.VaultKey != nil {
		t.Errorf("new password: %d %+v", status, resp)
	}
	if pulled := f.pull(resp.Token, 0); len(pulled.Records) != 0 || pulled.Revision != 0 {
		t.Errorf("records left: %+v", pulled)
	}
}

func TestUnknownFieldsAndHugeBodiesAreRefused(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.http.URL+"/api/prelogin", strings.NewReader(`{"username":"me","extra":1}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field: %d", resp.StatusCode)
	}
	huge := usernameRequest{strings.Repeat("a", maxSmallBody)}
	if status := f.call("POST", "/api/prelogin", "", huge, nil); status != http.StatusRequestEntityTooLarge {
		t.Errorf("huge body: %d", status)
	}
}

func TestClientIPTrustsOnlyALocalProxy(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("POST", "/api/login", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	if got := f.server.clientIP(req); got != "127.0.0.1" {
		t.Errorf("without -trust-proxy: %s", got)
	}
	f.server.trustProxy = true
	if got := f.server.clientIP(req); got != "203.0.113.9" {
		t.Errorf("through the proxy: %s", got)
	}
	req.RemoteAddr = "198.51.100.1:5000"
	if got := f.server.clientIP(req); got != "198.51.100.1" {
		t.Errorf("not through the proxy: %s", got)
	}
}
