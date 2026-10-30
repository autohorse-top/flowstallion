package cd

import (
	"maps"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var spec = CanarySpec{
	Name:        "demoapp",
	Namespace:   "flowstallion-cd-demo",
	StableImage: "flowstallion/demoapp:v1",
	CanaryImage: "flowstallion/demoapp:v2",
	Replicas:    2,
	Port:        8080,
}

func TestRenderCanaryManifests(t *testing.T) {
	out := RenderCanaryManifests(spec)
	docs := strings.Split(out, "\n---\n")
	if len(docs) != 5 {
		t.Fatalf("expected 5 documents, got %d", len(docs))
	}
	// Namespace
	if !strings.Contains(docs[0], "kind: Namespace") || !strings.Contains(docs[0], "name: flowstallion-cd-demo") {
		t.Errorf("namespace doc wrong:\n%s", docs[0])
	}
	// Stable deployment
	if !strings.Contains(docs[1], "kind: Deployment") ||
		!strings.Contains(docs[1], "name: demoapp") ||
		!strings.Contains(docs[1], "release: stable") ||
		!strings.Contains(docs[1], "image: flowstallion/demoapp:v1") ||
		!strings.Contains(docs[1], "replicas: 2") ||
		!strings.Contains(docs[1], "containerPort: 8080") ||
		!strings.Contains(docs[1], "readinessProbe") ||
		!strings.Contains(docs[1], "path: /metrics") {
		t.Errorf("stable deployment doc wrong:\n%s", docs[1])
	}
	// Stable service selects stable
	svc := docs[2]
	if !strings.Contains(svc, "kind: Service") || !strings.Contains(svc, "release: stable") ||
		!strings.Contains(svc, "port: 8080") {
		t.Errorf("stable service doc wrong:\n%s", svc)
	}
	// Canary deployment: 1 replica, canary image
	if !strings.Contains(docs[3], "name: demoapp-canary") ||
		!strings.Contains(docs[3], "release: canary") ||
		!strings.Contains(docs[3], "image: flowstallion/demoapp:v2") ||
		!strings.Contains(docs[3], "replicas: 1") ||
		!strings.Contains(docs[3], "path: /metrics") {
		t.Errorf("canary deployment doc wrong:\n%s", docs[3])
	}
	// Canary service selects canary
	if !strings.Contains(docs[4], "name: demoapp-canary") || !strings.Contains(docs[4], "release: canary") {
		t.Errorf("canary service doc wrong:\n%s", docs[4])
	}
	// Stable service must NOT select canary pods and vice versa.
	if strings.Contains(docs[2], "release: canary") {
		t.Errorf("stable service must not select canary:\n%s", docs[2])
	}
	if !strings.Contains(docs[4], "release: canary") || strings.Contains(docs[4], "name: demoapp\n") {
		t.Errorf("canary service doc wrong:\n%s", docs[4])
	}
}

func TestRenderPromoteService(t *testing.T) {
	out := RenderPromoteService(spec)
	if !strings.Contains(out, "kind: Service") ||
		!strings.Contains(out, "name: demoapp") ||
		!strings.Contains(out, "release: canary") ||
		!strings.Contains(out, "port: 8080") {
		t.Errorf("promote service wrong:\n%s", out)
	}
	// Must keep the stable service name (selector switch, not a new name).
	if strings.Contains(out, "name: demoapp-canary") {
		t.Errorf("promote service must keep stable service name:\n%s", out)
	}
}

// TestPromoteServiceSelectorMatchesCanaryPods is the F-T8-1 regression test:
// the promote Service keeps the stable name but its selector must exactly
// match the canary Deployment's pod labels ({app: <name>-canary, release:
// canary}). P3/P4 verified the selector text but not the endpoint match,
// which missed that "app" was derived from the service name.
func TestPromoteServiceSelectorMatchesCanaryPods(t *testing.T) {
	manifests := strings.Split(RenderCanaryManifests(spec), "\n---\n")
	canaryPodLabels := podLabels(t, unmarshalDoc(t, "canary deployment", manifests[3]))

	promoteSvc := unmarshalDoc(t, "promote service", RenderPromoteService(spec))
	sel := svcSelector(t, promoteSvc)
	if !maps.Equal(sel, canaryPodLabels) {
		t.Fatalf("promote service selector %v != canary pod labels %v (F-T8-1)", sel, canaryPodLabels)
	}
	// The promote doc must keep the stable service name (kubectl apply
	// updates the existing Service, it must not create a second one).
	if name, _ := promoteSvc["metadata"].(map[string]any)["name"].(string); name != spec.Name {
		t.Errorf("promote service name = %q, want %q", name, spec.Name)
	}
}

// TestServiceSelectorsMatchPodLabels guards against future svcDoc refactor
// regressions: every Service's selector must equal its owning Deployment's
// pod labels.
func TestServiceSelectorsMatchPodLabels(t *testing.T) {
	manifests := strings.Split(RenderCanaryManifests(spec), "\n---\n")
	if len(manifests) != 5 {
		t.Fatalf("expected 5 documents, got %d", len(manifests))
	}
	// docs: 0=Namespace 1=stable Deployment 2=stable Service
	//       3=canary Deployment 4=canary Service
	cases := []struct {
		name      string
		svcIdx    int
		depIdx    int
		expectSel map[string]any
	}{
		{"stable service", 2, 1, map[string]any{"app": "demoapp", "release": "stable"}},
		{"canary service", 4, 3, map[string]any{"app": "demoapp-canary", "release": "canary"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel := svcSelector(t, unmarshalDoc(t, "service", manifests[tc.svcIdx]))
			labels := podLabels(t, unmarshalDoc(t, "deployment", manifests[tc.depIdx]))
			if !maps.Equal(sel, labels) {
				t.Errorf("service selector %v != deployment pod labels %v", sel, labels)
			}
			if !maps.Equal(sel, tc.expectSel) {
				t.Errorf("service selector %v != expected %v", sel, tc.expectSel)
			}
		})
	}
	// Rollback path: RenderStableService must restore the stable selector.
	sel := svcSelector(t, unmarshalDoc(t, "stable service", RenderStableService(spec)))
	labels := podLabels(t, unmarshalDoc(t, "deployment", manifests[1]))
	if !maps.Equal(sel, labels) {
		t.Errorf("RenderStableService selector %v != stable deployment pod labels %v", sel, labels)
	}
}

// unmarshalDoc parses one YAML document, failing the test on error.
func unmarshalDoc(t *testing.T, what, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("%s unparseable: %v\n%s", what, err, doc)
	}
	return m
}

// podLabels extracts spec.template.metadata.labels from a Deployment doc.
func podLabels(t *testing.T, dep map[string]any) map[string]any {
	t.Helper()
	specM, _ := dep["spec"].(map[string]any)
	if specM == nil {
		t.Fatalf("deployment has no spec:\n%v", dep)
	}
	tmpl, _ := specM["template"].(map[string]any)
	if tmpl == nil {
		t.Fatalf("deployment has no pod template:\n%v", dep)
	}
	meta, _ := tmpl["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	if labels == nil {
		t.Fatalf("deployment has no pod template labels:\n%v", dep)
	}
	return labels
}

// svcSelector extracts spec.selector from a Service doc.
func svcSelector(t *testing.T, svc map[string]any) map[string]any {
	t.Helper()
	specM, _ := svc["spec"].(map[string]any)
	if specM == nil {
		t.Fatalf("service has no spec:\n%v", svc)
	}
	sel, _ := specM["selector"].(map[string]any)
	if sel == nil {
		t.Fatalf("service has no spec.selector:\n%v", svc)
	}
	return sel
}

func TestValidImage(t *testing.T) {
	good := []string{
		"flowstallion/demoapp:v1",
		"demoapp",
		"ghcr.io/flowstallion/demoapp:v1",
		"localhost:5000/repo:1.0",
		"ubuntu:22.04",
		"repo@sha256:" + strings.Repeat("a", 64),
	}
	for _, s := range good {
		if !ValidImage(s) {
			t.Errorf("ValidImage(%q) = false, want true", s)
		}
	}
	bad := []string{
		"",
		"flowstallion/demoapp:v1\n---\nkind: Secret",
		"img:v2 #\nimagePullSecrets: []",
		"img v1",
		"img\tv1",
		"img:5000/x:1:2",
		strings.Repeat("a", 300),
	}
	for _, s := range bad {
		if ValidImage(s) {
			t.Errorf("ValidImage(%q) = true, want false", s)
		}
	}
}

// TestRenderCanaryManifestsInjectionSafe is the M-1 regression test: a
// hostile canary image (newline + injected document) must remain a plain
// scalar inside the canary deployment — never change the document count
// or turn a doc into something else.
func TestRenderCanaryManifestsInjectionSafe(t *testing.T) {
	evil := spec
	evil.CanaryImage = "evil\n---\nkind: Secret\nmetadata:\n  name: pwn"
	out := RenderCanaryManifests(evil)
	docs := strings.Split(out, "\n---\n")
	if len(docs) != 5 {
		t.Fatalf("injection changed doc count: got %d, want 5", len(docs))
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(docs[3]), &m); err != nil {
		t.Fatalf("doc 3 unparseable: %v", err)
	}
	if m["kind"] != "Deployment" {
		t.Fatalf("doc 3 kind = %v, want Deployment", m["kind"])
	}
}

func TestManifestYAMLShape(t *testing.T) {
	// Sanity: rendered docs must be valid YAML (every doc has
	// apiVersion+kind). Uses yaml.v3 (already a dependency).
	out := RenderCanaryManifests(spec)
	docs := strings.Split(out, "\n---\n")
	for i, d := range docs {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("doc %d not valid YAML: %v\n%s", i, err, d)
		}
		if _, ok := m["apiVersion"]; !ok {
			t.Errorf("doc %d missing apiVersion", i)
		}
		if _, ok := m["kind"]; !ok {
			t.Errorf("doc %d missing kind", i)
		}
	}
}
