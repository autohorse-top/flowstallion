package cd

import (
	"maps"
	"strings"
	"testing"
)

// TestStrategyBasics is the table-driven check of the strategy abstraction:
// every strategy id (including empty/unknown, which must fall back to the
// canary strategy) yields the documented id / alternate name / replicas.
func TestStrategyBasics(t *testing.T) {
	tests := []struct {
		id       string
		wantID   string
		wantAlt  string
		wantRepl int
	}{
		{"canary", "canary", "demoapp-canary", 1},
		{"blue_green", "blue_green", "demoapp-alt", 2},
		{"", "canary", "demoapp-canary", 1},
		{"bogus", "canary", "demoapp-canary", 1},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			s := StrategyFor(tt.id)
			if s.ID() != tt.wantID {
				t.Errorf("ID() = %q, want %q", s.ID(), tt.wantID)
			}
			if got := s.AltName("demoapp"); got != tt.wantAlt {
				t.Errorf("AltName(demoapp) = %q, want %q", got, tt.wantAlt)
			}
			if got := s.AltReplicas(2); got != tt.wantRepl {
				t.Errorf("AltReplicas(2) = %d, want %d", got, tt.wantRepl)
			}
		})
	}
}

// TestAltNameHelper pins the package-level helper against the interface.
func TestAltNameHelper(t *testing.T) {
	tests := []struct {
		strategy string
		want     string
	}{
		{"canary", "demoapp-canary"},
		{"blue_green", "demoapp-alt"},
		{"", "demoapp-canary"},
	}
	for _, tt := range tests {
		t.Run(tt.strategy, func(t *testing.T) {
			if got := AltName("demoapp", tt.strategy); got != tt.want {
				t.Errorf("AltName(demoapp, %q) = %q, want %q", tt.strategy, got, tt.want)
			}
		})
	}
}

// TestRenderReleaseManifests checks the generalized renderer for both
// strategies: the alternate deployment carries the strategy's alt name,
// release label, image and replica count, and the alternate Service selects
// exactly those pods.
func TestRenderReleaseManifests(t *testing.T) {
	tests := []struct {
		name       string
		altName    string
		altRelease string
		altRepl    int
	}{
		{name: "canary", altName: "demoapp-canary", altRelease: "canary", altRepl: 1},
		{name: "blue_green", altName: "demoapp-alt", altRelease: "blue_green", altRepl: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := strings.Split(
				RenderReleaseManifests(spec, tt.altName, tt.altRelease, tt.altRepl),
				"\n---\n")
			if len(docs) != 5 {
				t.Fatalf("expected 5 documents, got %d", len(docs))
			}
			// Stable deployment untouched by the strategy.
			stableDep := unmarshalDoc(t, "stable deployment", docs[1])
			if name, _ := stableDep["metadata"].(map[string]any)["name"].(string); name != spec.Name {
				t.Errorf("stable deployment name = %q, want %q", name, spec.Name)
			}
			if got := deployReplicas(t, stableDep); got != spec.Replicas {
				t.Errorf("stable replicas = %d, want %d", got, spec.Replicas)
			}
			// Alternate deployment.
			altDep := unmarshalDoc(t, "alt deployment", docs[3])
			if name, _ := altDep["metadata"].(map[string]any)["name"].(string); name != tt.altName {
				t.Errorf("alt deployment name = %q, want %q", name, tt.altName)
			}
			labels := podLabels(t, altDep)
			if labels["app"] != tt.altName || labels["release"] != tt.altRelease {
				t.Errorf("alt pod labels = %v, want app=%s release=%s",
					labels, tt.altName, tt.altRelease)
			}
			if got := deployReplicas(t, altDep); got != tt.altRepl {
				t.Errorf("alt replicas = %d, want %d", got, tt.altRepl)
			}
			if !strings.Contains(docs[3], "image: flowstallion/demoapp:v2") {
				t.Errorf("alt deployment must use the new image:\n%s", docs[3])
			}
			// Alternate service selects the alternate pods exactly.
			altSvc := unmarshalDoc(t, "alt service", docs[4])
			sel := svcSelector(t, altSvc)
			if !maps.Equal(sel, labels) {
				t.Errorf("alt service selector %v != alt pod labels %v", sel, labels)
			}
			// Stable service keeps its own selector.
			stableSel := svcSelector(t, unmarshalDoc(t, "stable service", docs[2]))
			if !maps.Equal(stableSel, map[string]any{"app": spec.Name, "release": "stable"}) {
				t.Errorf("stable service selector = %v", stableSel)
			}
		})
	}
}

// TestSwitchServiceSelectorMatchesAltPods is the generalized F-T8-1
// regression: for both strategies the switch Service keeps the stable
// service name, and its selector must equal the alternate deployment's pod
// labels verbatim (a mismatch leaves the stable Service with zero endpoints
// after the switch).
func TestSwitchServiceSelectorMatchesAltPods(t *testing.T) {
	for _, st := range []Strategy{CanaryStrategy{}, BlueGreenStrategy{}} {
		t.Run(st.ID(), func(t *testing.T) {
			alt := st.AltName(spec.Name)
			docs := strings.Split(
				RenderReleaseManifests(spec, alt, st.ID(), st.AltReplicas(spec.Replicas)),
				"\n---\n")
			altLabels := podLabels(t, unmarshalDoc(t, "alt deployment", docs[3]))

			switchSvc := unmarshalDoc(t, "switch service",
				RenderSwitchService(spec, alt, st.ID()))
			sel := svcSelector(t, switchSvc)
			if !maps.Equal(sel, altLabels) {
				t.Fatalf("switch service selector %v != alt pod labels %v (F-T8-1)",
					sel, altLabels)
			}
			// The switch doc must keep the stable service name (kubectl
			// apply updates the existing Service; a second name would leave
			// the old Service dangling).
			if name, _ := switchSvc["metadata"].(map[string]any)["name"].(string); name != spec.Name {
				t.Errorf("switch service name = %q, want stable name %q", name, spec.Name)
			}
		})
	}
}

// TestStrategyWrappersParity pins the legacy export functions to the
// generalized renderers so the canary path stays byte-identical.
func TestStrategyWrappersParity(t *testing.T) {
	if got, want := RenderCanaryManifests(spec),
		RenderReleaseManifests(spec, "demoapp-canary", "canary", 1); got != want {
		t.Errorf("RenderCanaryManifests diverges from generalized renderer:\n%s", got)
	}
	if got, want := RenderPromoteService(spec),
		RenderSwitchService(spec, "demoapp-canary", "canary"); got != want {
		t.Errorf("RenderPromoteService diverges from generalized renderer:\n%s", got)
	}
}

// deployReplicas extracts spec.replicas from a parsed Deployment doc.
func deployReplicas(t *testing.T, dep map[string]any) int {
	t.Helper()
	specM, _ := dep["spec"].(map[string]any)
	if specM == nil {
		t.Fatalf("deployment has no spec:\n%v", dep)
	}
	repl, _ := specM["replicas"].(int)
	return repl
}
