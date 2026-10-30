package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/store"
)

func postCanary(t *testing.T, ts *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(ts.URL+"/api/canaries", "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("POST /api/canaries: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(rb) > 0 {
		if err := json.Unmarshal(rb, &out); err != nil {
			t.Fatalf("decode response %d: %v\n%s", resp.StatusCode, err, rb)
		}
	}
	return resp.StatusCode, out
}

var baseCanaryBody = map[string]any{
	"name":         "demoapp",
	"namespace":    "flowstallion-cd-demo",
	"stable_image": "flowstallion/demoapp:v1",
	"canary_image": "flowstallion/demoapp:v2",
	"replicas":     2,
	"port":         8080,
	"threshold":    0.3,
	"min_samples":  5,
	"warmup_s":     4,
	"observe_s":    8,
}

func TestCanaryCreateValidate(t *testing.T) {
	ts, _ := newTestServer(t)
	cases := []map[string]any{
		{"name": "DemoApp"},                      // uppercase
		{"name": "x-"},                           // trailing dash
		{"name": ""},                             // empty
		{"name": strings.Repeat("a", 64)},        // too long
		{"stable_image": ""},                     // missing
		{"canary_image": ""},                     // missing
		{"threshold": 0},                         // out of range
		{"threshold": 1.5},                       // out of range
		{"replicas": 0},                          // out of range
		{"port": 0},                              // out of range
		{"min_samples": 0},                       // out of range
		{"warmup_s": 0},                          // out of range
		{"namespace": "BAD_NS"},                  // bad namespace
		{"stable_image": "x\n---\nkind: Secret"}, // M-1: image injection vector
		{"canary_image": "img v1"},               // M-1: invalid image reference
	}
	for i, patch := range cases {
		body := map[string]any{}
		for k, v := range baseCanaryBody {
			body[k] = v
		}
		for k, v := range patch {
			body[k] = v
		}
		code, out := postCanary(t, ts, body)
		if code != http.StatusBadRequest {
			t.Fatalf("case %d (%v): status = %d, want 400; body=%v", i, patch, code, out)
		}
		if _, ok := out["problems"]; !ok {
			t.Fatalf("case %d: response missing problems list: %v", i, out)
		}
	}
}

func TestCanaryCreateOKAndDuplicate(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%v", code, out)
	}
	if out["state"] != "pending" {
		t.Fatalf("state = %v, want pending", out["state"])
	}

	// A second active canary with the same name must 409.
	code2, _ := postCanary(t, ts, baseCanaryBody)
	if code2 != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409", code2)
	}

	// A different name is fine.
	other := map[string]any{}
	for k, v := range baseCanaryBody {
		other[k] = v
	}
	other["name"] = "other-app"
	code3, _ := postCanary(t, ts, other)
	if code3 != http.StatusCreated {
		t.Fatalf("different name status = %d, want 201", code3)
	}
}

func TestCanaryListAndGet(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := int64(out["id"].(float64))

	resp, err := http.Get(ts.URL + "/api/canaries")
	if err != nil {
		t.Fatalf("GET list: %v", err)
	}
	defer resp.Body.Close()
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	if list[0]["name"] != "demoapp" {
		t.Fatalf("list[0].name = %v", list[0]["name"])
	}
	if list[0]["state"] != "pending" {
		t.Fatalf("list[0].state = %v, want pending", list[0]["state"])
	}

	resp2, err := http.Get(fmt.Sprintf("%s/api/canaries/%d", ts.URL, id))
	if err != nil {
		t.Fatalf("GET detail: %v", err)
	}
	defer resp2.Body.Close()
	var detail map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	can := detail["canary"].(map[string]any)
	if can["name"] != "demoapp" || can["state"] != "pending" {
		t.Fatalf("detail wrong: %v", can)
	}
	evs, ok := detail["events"].([]any)
	if !ok || len(evs) != 0 {
		t.Fatalf("events should be empty initially, got %v", detail["events"])
	}

	// Unknown id -> 404.
	resp404, err := http.Get(ts.URL + "/api/canaries/99999")
	if err != nil {
		t.Fatalf("GET 404: %v", err)
	}
	defer resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id status = %d, want 404", resp404.StatusCode)
	}
}

// TestCanaryNameCollision is the m-1 regression: a new release whose
// K8s object names would collide with another active release's objects
// (stable "X" vs canary "X-canary") must be rejected with 409.
func TestCanaryNameCollision(t *testing.T) {
	ts, _ := newTestServer(t)
	code, _ := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	other := map[string]any{}
	for k, v := range baseCanaryBody {
		other[k] = v
	}
	// "demoapp-canary"'s stable Deployment would be named
	// "demoapp-canary" == the existing release's canary Deployment.
	other["name"] = "demoapp-canary"
	code2, _ := postCanary(t, ts, other)
	if code2 != http.StatusConflict {
		t.Fatalf("collision status = %d, want 409", code2)
	}
}

// TestCanaryNameCollisionPromoted is the F-3 regression: a promoted release
// leaves deployment "P-canary" (now production) and the stable-named
// Service "P" behind in the namespace. A new release whose objects would
// reuse those names would silently rewrite live production objects, so it
// must be rejected with 409 until the leftovers are cleaned up.
func TestCanaryNameCollisionPromoted(t *testing.T) {
	// Case 1: promoted "demoapp" leaves deploy demoapp-canary + svc demoapp.
	ts, srv := newTestServer(t)
	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := int64(out["id"].(float64))
	if err := srv.Store.SetCanaryState(id, store.CanaryPromoted,
		"promoted: canary healthy for full window", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set promoted: %v", err)
	}
	body := map[string]any{}
	for k, v := range baseCanaryBody {
		body[k] = v
	}
	cases := []struct {
		name string
		want int
	}{
		{"demoapp", http.StatusConflict},        // N == P: would overwrite production svc
		{"demoapp-canary", http.StatusConflict}, // N == P-canary: would overwrite production deploy
		{"other-app", http.StatusCreated},       // no collision
	}
	for _, tc := range cases {
		body["name"] = tc.name
		code, _ := postCanary(t, ts, body)
		if code != tc.want {
			t.Fatalf("case %q: status = %d, want %d", tc.name, code, tc.want)
		}
	}

	// Case 2: promoted "web-canary" leaves svc web-canary behind; a new
	// release "web" would create its canary Service on top of it.
	ts2, srv2 := newTestServer(t)
	wc := map[string]any{}
	for k, v := range baseCanaryBody {
		wc[k] = v
	}
	wc["name"] = "web-canary"
	code, out = postCanary(t, ts2, wc)
	if code != http.StatusCreated {
		t.Fatalf("create web-canary: %d %v", code, out)
	}
	id2 := int64(out["id"].(float64))
	if err := srv2.Store.SetCanaryState(id2, store.CanaryPromoted,
		"promoted", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set promoted: %v", err)
	}
	body["name"] = "web" // "web" + "-canary" == "web-canary" == promoted name
	code, _ = postCanary(t, ts2, body)
	if code != http.StatusConflict {
		t.Fatalf("N-canary == P: status = %d, want 409", code)
	}
}

// TestCanaryStrategy covers the strategy field: blue_green accepted +
// persisted + echoed, invalid values rejected 400, omitted defaults to
// canary, strategy-aware 63-char object-name cap, and cross-strategy
// object-name collision (active "web"(blue_green) vs new canary "web-alt").
func TestCanaryStrategy(t *testing.T) {
	ts, _ := newTestServer(t)

	// 1) blue_green accepted, persisted, echoed.
	body := map[string]any{}
	for k, v := range baseCanaryBody {
		body[k] = v
	}
	body["strategy"] = "blue_green"
	code, out := postCanary(t, ts, body)
	if code != http.StatusCreated {
		t.Fatalf("create blue_green status = %d, want 201; body=%v", code, out)
	}
	id := int64(out["id"].(float64))
	resp, err := http.Get(ts.URL + "/api/canaries/" + strconv.FormatInt(id, 10))
	if err != nil {
		t.Fatalf("get canary: %v", err)
	}
	var detail struct {
		Canary map[string]any `json:"canary"`
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(rb, &detail); err != nil {
		t.Fatalf("decode detail: %v\n%s", err, rb)
	}
	if detail.Canary["strategy"] != "blue_green" {
		t.Fatalf("echoed strategy = %v, want blue_green; body=%s", detail.Canary["strategy"], rb)
	}

	// 2) invalid strategies rejected with 400 + problems.
	for _, bad := range []string{"rolling", "BLUE_GREEN", "canary "} {
		b2 := map[string]any{}
		for k, v := range baseCanaryBody {
			b2[k] = v
		}
		b2["name"] = "strategy-bad"
		b2["strategy"] = bad
		code2, out2 := postCanary(t, ts, b2)
		if code2 != http.StatusBadRequest {
			t.Fatalf("strategy %q: status = %d, want 400; body=%v", bad, code2, out2)
		}
		if _, ok := out2["problems"]; !ok {
			t.Fatalf("strategy %q: response missing problems: %v", bad, out2)
		}
	}

	// 3) omitted strategy defaults to canary.
	b3 := map[string]any{}
	for k, v := range baseCanaryBody {
		b3[k] = v
	}
	b3["name"] = "strategy-default"
	code3, out3 := postCanary(t, ts, b3)
	if code3 != http.StatusCreated {
		t.Fatalf("create default strategy: %d %v", code3, out3)
	}
	id3 := int64(out3["id"].(float64))
	resp3, err := http.Get(ts.URL + "/api/canaries/" + strconv.FormatInt(id3, 10))
	if err != nil {
		t.Fatalf("get canary: %v", err)
	}
	rb3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	var d3 struct {
		Canary map[string]any `json:"canary"`
	}
	if err := json.Unmarshal(rb3, &d3); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if d3.Canary["strategy"] != "canary" {
		t.Fatalf("default strategy = %v, want canary", d3.Canary["strategy"])
	}

	// 4) strategy-aware 63-char object-name cap:
	//    canary:  56+7  = 63 ok,  57+7  = 64 reject
	//    blue_green: 59+4 = 63 ok,  60+4 = 64 reject
	longCases := []struct {
		name     string
		strategy string
		want     int
	}{
		{strings.Repeat("a", 56), "canary", http.StatusCreated},
		{strings.Repeat("a", 57), "canary", http.StatusBadRequest},
		{strings.Repeat("b", 59), "blue_green", http.StatusCreated},
		{strings.Repeat("b", 60), "blue_green", http.StatusBadRequest},
	}
	for _, tc := range longCases {
		b4 := map[string]any{}
		for k, v := range baseCanaryBody {
			b4[k] = v
		}
		b4["name"] = tc.name
		b4["strategy"] = tc.strategy
		code4, _ := postCanary(t, ts, b4)
		if code4 != tc.want {
			t.Fatalf("name len %d strategy %s: status = %d, want %d", len(tc.name), tc.strategy, code4, tc.want)
		}
	}

	// 5) cross-strategy collision: active blue_green "web" owns {web, web-alt};
	//    a new canary named "web-alt" would reuse the alt object name.
	b5 := map[string]any{}
	for k, v := range baseCanaryBody {
		b5[k] = v
	}
	b5["name"] = "web"
	b5["strategy"] = "blue_green"
	code5, _ := postCanary(t, ts, b5)
	if code5 != http.StatusCreated {
		t.Fatalf("create active blue_green web: %d", code5)
	}
	b6 := map[string]any{}
	for k, v := range baseCanaryBody {
		b6[k] = v
	}
	b6["name"] = "web-alt" // base name == the blue_green release's alt object
	code6, _ := postCanary(t, ts, b6)
	if code6 != http.StatusConflict {
		t.Fatalf("cross-strategy collision status = %d, want 409", code6)
	}
}

// TestCanarySourceRef is the P4 feature: an optional source_ref (git commit
// sha or branch name) anchors the Release→Commit edge in the knowledge graph.
// Table-driven: valid refs (branch/short sha/full sha/boundary length) must
// be accepted (201) and echoed back in the GET detail; invalid refs (too
// long, space, injection characters) must be rejected 400 with problems.
func TestCanarySourceRef(t *testing.T) {
	ts, _ := newTestServer(t)
	cases := []struct {
		ref  string
		want int
	}{
		{"main", http.StatusCreated},                     // branch name
		{"abc123DEF", http.StatusCreated},                // short sha (mixed case)
		{strings.Repeat("a", 40), http.StatusCreated},    // full sha length
		{"feature/fix-1.2_3", http.StatusCreated},        // slash/dot/underscore
		{strings.Repeat("b", 64), http.StatusCreated},    // 64-char boundary (ok)
		{strings.Repeat("c", 65), http.StatusBadRequest}, // 65 chars: too long
		{"abc 123", http.StatusBadRequest},               // space
		{"abc;def", http.StatusBadRequest},               // shell metachar
		{"abc'def", http.StatusBadRequest},               // quote
		{"abc`def", http.StatusBadRequest},               // backtick
		{"abc\ndef", http.StatusBadRequest},              // newline
	}
	for i, tc := range cases {
		body := map[string]any{}
		for k, v := range baseCanaryBody {
			body[k] = v
		}
		body["name"] = fmt.Sprintf("sr%d", i)
		body["source_ref"] = tc.ref
		code, out := postCanary(t, ts, body)
		if code != tc.want {
			t.Fatalf("case %d (ref %q): status = %d, want %d; body=%v", i, tc.ref, code, tc.want, out)
		}
		if tc.want == http.StatusBadRequest {
			if _, ok := out["problems"]; !ok {
				t.Fatalf("case %d: 400 response missing problems: %v", i, out)
			}
			continue
		}
		id := int64(out["id"].(float64))
		resp, err := http.Get(fmt.Sprintf("%s/api/canaries/%d", ts.URL, id))
		if err != nil {
			t.Fatalf("case %d: GET: %v", i, err)
		}
		var detail map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
			resp.Body.Close()
			t.Fatalf("case %d: decode detail: %v", i, err)
		}
		resp.Body.Close()
		can, ok := detail["canary"].(map[string]any)
		if !ok {
			t.Fatalf("case %d: detail missing canary: %v", i, detail)
		}
		if can["source_ref"] != tc.ref {
			t.Fatalf("case %d: echoed source_ref = %v, want %q", i, can["source_ref"], tc.ref)
		}
	}
}

// TestCanarySourceRefOmitted: a POST without source_ref must succeed (201)
// and the detail must not echo a source_ref (omitempty / empty default).
func TestCanarySourceRefOmitted(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%v", code, out)
	}
	id := int64(out["id"].(float64))
	resp, err := http.Get(fmt.Sprintf("%s/api/canaries/%d", ts.URL, id))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var detail map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	can, ok := detail["canary"].(map[string]any)
	if !ok {
		t.Fatalf("detail missing canary: %v", detail)
	}
	if v, present := can["source_ref"]; present && v != "" {
		t.Fatalf("omitted source_ref should be empty, got %v", v)
	}
}

// TestCanaryEventJSONStableID pins the M-3 contract: the detail endpoint's
// event list carries the store row id (a stable identifier), not a window
// position, so graph collectors can key Event nodes across window slides.
func TestCanaryEventJSONStableID(t *testing.T) {
	ts, srv := newTestServer(t)
	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := int64(out["id"].(float64))
	if err := srv.Store.InsertCanaryEvent(id, store.CanaryApplying, "apply ok"); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	resp, err := http.Get(fmt.Sprintf("%s/api/canaries/%d", ts.URL, id))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var detail map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	evs, ok := detail["events"].([]any)
	if !ok || len(evs) != 1 {
		t.Fatalf("events = %v, want exactly 1 event", detail["events"])
	}
	ev, ok := evs[0].(map[string]any)
	if !ok {
		t.Fatalf("event[0] is not an object: %v", evs[0])
	}
	if got, present := ev["id"]; !present || got != float64(1) {
		t.Fatalf("event[0].id = %v (present=%v), want 1 (store row id)", got, present)
	}
}

// fakeK is a no-op Kubectl stub that records all invocations.
type fakeK struct{ calls []string }

func (k *fakeK) Run(args []string, stdin string) (string, error) {
	k.calls = append(k.calls, strings.Join(args, " "))
	return "", nil
}

// TestCanaryRollback (P7⑧) exercises the POST /api/canaries/{id}/rollback
// endpoint: 400 bad id, 404 unknown, 503 controller not wired, 409 terminal,
// 200 success (state transition + kubectl delete + event), and default reason.
func TestCanaryRollback(t *testing.T) {
	ts, srv := newTestServer(t)
	c := ts.Client()
	base := ts.URL

	// 400: non-numeric id
	if code, _ := doJSON(t, c, "POST", base+"/api/canaries/abc/rollback", nil); code != http.StatusBadRequest {
		t.Fatalf("bad id: got %d, want 400", code)
	}

	// 404: unknown numeric id
	if code, _ := doJSON(t, c, "POST", base+"/api/canaries/99999/rollback", nil); code != http.StatusNotFound {
		t.Fatalf("unknown id: got %d, want 404", code)
	}

	// 503: controller not wired yet
	code, out := postCanary(t, ts, baseCanaryBody)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := int64(out["id"].(float64))
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/canaries/%d/rollback", base, id), nil); code != http.StatusServiceUnavailable {
		t.Fatalf("nil controller: got %d, want 503", code)
	}

	// Wire a fake controller
	fk := &fakeK{}
	srv.CanaryCtl = cd.NewController(srv.Store, fk)

	// 409: terminal state
	other := map[string]any{}
	for k, v := range baseCanaryBody {
		other[k] = v
	}
	other["name"] = "webapp"
	code, out = postCanary(t, ts, other)
	if code != http.StatusCreated {
		t.Fatalf("create webapp: %d %v", code, out)
	}
	id2 := int64(out["id"].(float64))
	if err := srv.Store.SetCanaryState(id2, store.CanaryPromoted, "promoted", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set promoted: %v", err)
	}
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/canaries/%d/rollback", base, id2), nil); code != http.StatusConflict {
		t.Fatalf("terminal rollback: got %d, want 409", code)
	}

	// 200: active canary + reason
	code, out = doJSON(t, c, "POST", fmt.Sprintf("%s/api/canaries/%d/rollback", base, id),
		map[string]any{"reason": "err spike"})
	if code != http.StatusOK {
		t.Fatalf("rollback: got %d, want 200 (body=%v)", code, out)
	}
	if out["state"] != "rolled_back" {
		t.Fatalf("state = %v, want rolled_back", out["state"])
	}
	cr, err := srv.Store.GetCanary(id)
	if err != nil {
		t.Fatalf("get canary: %v", err)
	}
	if cr.State != store.CanaryRolledBack {
		t.Fatalf("store state = %q, want rolled_back", cr.State)
	}
	if cr.Reason != "err spike" {
		t.Fatalf("store reason = %q, want err spike", cr.Reason)
	}
	if len(fk.calls) != 2 {
		t.Fatalf("kubectl calls = %d, want 2 (delete deploy + delete svc)", len(fk.calls))
	}
	evs, err := srv.Store.EventsOf(id)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(evs) == 0 || evs[len(evs)-1].State != store.CanaryRolledBack {
		t.Fatalf("last event = %+v, want state rolled_back", evs)
	}

	// Default reason when body omitted
	third := map[string]any{}
	for k, v := range baseCanaryBody {
		third[k] = v
	}
	third["name"] = "thirdapp"
	code, out = postCanary(t, ts, third)
	if code != http.StatusCreated {
		t.Fatalf("create third: %d %v", code, out)
	}
	id3 := int64(out["id"].(float64))
	if code, _ := doJSON(t, c, "POST", fmt.Sprintf("%s/api/canaries/%d/rollback", base, id3), nil); code != http.StatusOK {
		t.Fatalf("rollback default reason: got %d, want 200", code)
	}
	cr3, _ := srv.Store.GetCanary(id3)
	if cr3.Reason != "manual rollback" {
		t.Fatalf("default reason = %q, want manual rollback", cr3.Reason)
	}
}

// TestCanaryRollbackConflictMapping (K1): a state-CAS conflict raised by a
// concurrent driver must surface as HTTP 409 (retryable), while any other
// controller failure stays 500.
func TestCanaryRollbackConflictMapping(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		want   int
		substr string
	}{
		{"bare conflict is 409", store.ErrCanaryStateConflict, http.StatusConflict, "concurrent"},
		{"wrapped conflict is 409",
			fmt.Errorf("store: canary 7 state conflict: expected %q: %w", "observing", store.ErrCanaryStateConflict),
			http.StatusConflict, "concurrent"},
		{"generic failure is 500", errors.New("kubectl delete boom"), http.StatusInternalServerError, "kubectl delete boom"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := canaryRollbackStatus(7, tc.err)
			if code != tc.want {
				t.Fatalf("status = %d, want %d (msg %q)", code, tc.want, msg)
			}
			if !strings.Contains(msg, tc.substr) {
				t.Fatalf("message %q does not contain %q", msg, tc.substr)
			}
		})
	}
}
