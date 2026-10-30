package cd

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CanarySpec describes the objects the canary controller creates.
type CanarySpec struct {
	Name        string
	Namespace   string
	StableImage string
	CanaryImage string
	Replicas    int
	Port        int
}

// imageRe is a permissive Docker image reference pattern:
// optional registry[domain[:port]]/ prefix, a repository path, an optional
// :tag and/or an @sha256: digest. It rejects whitespace, newlines, '#' and
// any other character that could terminate a scalar or start a new YAML
// document/key (the M-1 injection vector).
var imageRe = regexp.MustCompile(
	`^(?:[A-Za-z0-9.-]+(?::\d{1,5})?/)?` + // optional registry[domain:port]/
		`[A-Za-z0-9][A-Za-z0-9._/-]*` + // repository path
		`(?::[A-Za-z0-9][A-Za-z0-9._-]{0,127})?` + // optional tag
		`(@sha256:[a-f0-9]{64})?$`)

// ValidImage reports whether s is a plausible Docker image reference.
// The map-based renderer below makes injection structurally impossible;
// this check additionally rejects nonsense early, at the API layer.
func ValidImage(s string) bool {
	return len(s) > 0 && len(s) <= 255 && imageRe.MatchString(s)
}

// RenderReleaseManifests renders the initial multi-document YAML for a
// strategy-driven release: namespace, stable Deployment + Service, and the
// strategy's alternate Deployment + Service. altName/altRelease identify the
// alternate objects (their pod labels are app=altName, release=altRelease);
// altReplicas is the alternate deployment's replica count.
//
// Documents are built as typed maps and marshalled with yaml.Marshal, so
// user-controlled fields (name, namespace, images) can never escape their
// value position or inject extra documents/keys (M-1).
func RenderReleaseManifests(s CanarySpec, altName, altRelease string, altReplicas int) string {
	return joinDocs([]any{
		nsDoc(s.Namespace),
		deployDoc(s.Name, s.Namespace, "stable", s.StableImage, s.Replicas, s.Port),
		svcDoc(s.Name, s.Namespace, s.Name, "stable", s.Port),
		deployDoc(altName, s.Namespace, altRelease, s.CanaryImage, altReplicas, s.Port),
		svcDoc(altName, s.Namespace, altName, altRelease, s.Port),
	})
}

// RenderCanaryManifests renders the initial multi-document YAML for the
// isolated-canary strategy: namespace, stable Deployment + Service, and
// canary Deployment + Service.
func RenderCanaryManifests(s CanarySpec) string {
	return RenderReleaseManifests(s, s.Name+"-canary", "canary", 1)
}

// RenderSwitchService renders the Service manifest that switches the stable
// service's selector to the strategy's alternate pods. It keeps the stable
// service name (kubectl apply updates the existing Service) but must select
// the alternate pods by their app label altName (F-T8-1: deriving the app
// label from the service name left the selector matching no pod, so the
// stable Service ended up with zero endpoints after every promote).
func RenderSwitchService(s CanarySpec, altName, altRelease string) string {
	return joinDocs([]any{svcDoc(s.Name, s.Namespace, altName, altRelease, s.Port)})
}

// RenderPromoteService renders the Service manifest that switches the
// stable service selector to the canary pods.
func RenderPromoteService(s CanarySpec) string {
	return RenderSwitchService(s, s.Name+"-canary", "canary")
}

// RenderStableService renders the stable-selector variant of the stable
// Service. Used by the promote-failure recovery path (F-1) to undo a
// selector switch after a release fails terminally mid-promote.
func RenderStableService(s CanarySpec) string {
	return joinDocs([]any{svcDoc(s.Name, s.Namespace, s.Name, "stable", s.Port)})
}

// joinDocs marshals each document and joins them with YAML separators.
// Document order is preserved; key order within a document is irrelevant
// to kubectl.
func joinDocs(docs []any) string {
	parts := make([]string, 0, len(docs))
	for _, d := range docs {
		b, err := yaml.Marshal(d)
		if err != nil {
			panic(fmt.Sprintf("cd: yaml.Marshal failed: %v", err))
		}
		parts = append(parts, string(bytes.TrimSpace(b)))
	}
	return strings.Join(parts, "\n---\n") + "\n"
}

func nsDoc(ns string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": ns},
	}
}

func deployDoc(name, ns, release, image string, replicas, port int) map[string]any {
	labels := map[string]any{"app": name, "release": release}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name": name, "namespace": ns, "labels": labels,
		},
		"spec": map[string]any{
			"replicas": replicas,
			"selector": map[string]any{"matchLabels": labels},
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": image,
							"ports": []any{map[string]any{"containerPort": port}},
							"readinessProbe": map[string]any{
								"httpGet":             map[string]any{"path": "/metrics", "port": port},
								"initialDelaySeconds": 2,
								"periodSeconds":       2,
							},
						},
					},
				},
			},
		},
	}
}

// svcDoc renders a Service named "name" that selects pods by the labels
// {app: app, release: release}. The app label is passed explicitly instead
// of being derived from the service name, because the promote switch
// reuses the stable service name while pointing at the canary pods
// (whose app label is "<name>-canary") — see F-T8-1.
func svcDoc(name, ns, app, release string, port int) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"selector": map[string]any{"app": app, "release": release},
			"ports":    []any{map[string]any{"port": port, "targetPort": port}},
		},
	}
}
