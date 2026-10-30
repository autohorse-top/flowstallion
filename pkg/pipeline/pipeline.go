// Package pipeline: flowstallion.yaml DSL — schema, parsing and validation.
//
// ParseYAML is the single entry point: it deserialises the YAML document and
// runs the full structural validation, returning every problem found in one
// aggregated error (each message carries a field path such as
// "pipeline.steps[1].id"). The YAML layer is strictly declarative: no
// command referenced in the document is ever executed here.
package pipeline

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// MaxPipelineNameLength is the maximum length of pipeline.name.
	MaxPipelineNameLength = 128
	// MaxStepIDLength is the maximum length of a step id.
	MaxStepIDLength = 64
	// MaxBranchLength is the maximum length of a trigger branch pattern.
	MaxBranchLength = 256
	// MaxCronLength is the maximum length of a schedule cron expression.
	MaxCronLength = 64
	// MaxSecretNameLength is the maximum length of a secret name.
	MaxSecretNameLength = 128
	// MaxNotifications bounds pipeline.notifications (P7⑦).
	MaxNotifications = 10
	// MaxNotificationURLLength bounds pipeline.notifications[i].url (P7⑦).
	MaxNotificationURLLength = 2048

	// MinConcurrency / MaxConcurrency bound pipeline.concurrency.
	MinConcurrency = 1
	MaxConcurrency = 100

	// MinStepTimeout / MaxStepTimeout bound step.timeout (seconds).
	MinStepTimeout = 1
	MaxStepTimeout = 604800 // 7 days

	// DefaultStepTimeout is applied when step.timeout is omitted.
	DefaultStepTimeout = 1800 // 30 minutes

	// MinCanaryWeight / MaxCanaryWeight bound the CD steps' canary.weight
	// (k8s_canary / k8s_blue_green, P7⑤).
	MinCanaryWeight = 1
	MaxCanaryWeight = 100

	// DefaultCanaryWeight is applied when canary.weight is omitted. v1 is an
	// isolation canary (no traffic split), so the weight is informational
	// only: it is recorded in step outputs but never applied to k8s objects.
	DefaultCanaryWeight = 10
)

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

var (
	// pipelineNamePattern: alphanumeric first char, then alnum/_/-, ≤128 total.
	pipelineNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

	// stepIDPattern: alphanumeric first char, then alnum/_/-, ≤64 total.
	// NOTE: intentionally differs from stepNamePattern in steps.go (which
	// requires a leading letter) — the DSL allows digits as the first char.
	stepIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

	// secretNamePattern: alnum plus dot, underscore, hyphen; ≥1 char.
	secretNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

	// k8sNamePattern: RFC 1123 subdomain (k8s object / namespace names):
	// lowercase alnum and '-', must start and end with an alnum, ≤63 chars.
	// Used for k8s_canary step namespace / deployment (P7⑤).
	k8sNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

	// k8sContextPattern: kube context name — conservative charset, ≤128.
	k8sContextPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// k8sAltSuffixCanary / k8sAltSuffixBlueGreen are the strategy-specific
// suffixes appended to the deployment name for the alternate (new-version)
// K8s object. They mirror pkg/cd's naming (canary "-canary", blue_green
// "-alt") so the pipeline can reject deployment names whose alternate would
// exceed K8s' 63-char object-name limit before a run is created.
const (
	k8sAltSuffixCanary    = "-canary"
	k8sAltSuffixBlueGreen = "-alt"
)

// validTriggerEvents is the closed set of accepted trigger events.
var validTriggerEvents = map[string]bool{
	"push":         true,
	"pull_request": true,
	"schedule":     true,
	"manual":       true,
}

// validNotificationTypes is the closed set of accepted notification types (P7⑦).
var validNotificationTypes = map[string]bool{
	"webhook": true,
}

// ValidSecretName reports whether s is a legal secret name: it must match
// secretNamePattern (alnum plus dot, underscore, hyphen, ≥1 char) and be at
// most MaxSecretNameLength characters.
func ValidSecretName(s string) bool {
	return len(s) > 0 && len(s) <= MaxSecretNameLength && secretNamePattern.MatchString(s)
}

// ---------------------------------------------------------------------------
// Exported types
// ---------------------------------------------------------------------------

// Trigger is one pipeline trigger rule.
type Trigger struct {
	Event    string   `yaml:"event" json:"event"`                           // required: push | pull_request | schedule | manual
	Branches []string `yaml:"branches,omitempty" json:"branches,omitempty"` // optional; each ≤ MaxBranchLength
	Cron     string   `yaml:"cron,omitempty" json:"cron,omitempty"`         // required only when Event == "schedule"; ≤ MaxCronLength
}

// Notification is one pipeline notification rule (P7⑦).
//
// A webhook endpoint that receives a JSON POST when a run reaches a terminal
// state (success / failed / canceled) or when a canary release is rolled back.
type Notification struct {
	Type string `yaml:"type" json:"type"` // required: "webhook"
	URL  string `yaml:"url" json:"url"`   // required: http(s) endpoint with host
}

// StepDef is one pipeline step in the DSL.
type StepDef struct {
	ID       string            `yaml:"id" json:"id"`                           // required; unique within the pipeline
	Image    string            `yaml:"image" json:"image"`                     // required; container image (default type) or target image template (docker_build)
	Commands []string          `yaml:"commands" json:"commands"`               // required for default steps; forbidden for docker_build
	Needs    []string          `yaml:"needs,omitempty" json:"needs,omitempty"` // optional; step ids, must form a DAG
	Env      map[string]string `yaml:"env,omitempty" json:"env,omitempty"`     // optional
	Timeout  int               `yaml:"timeout" json:"timeout"`                 // seconds; 1..MaxStepTimeout, defaults to DefaultStepTimeout

	// P7④: docker_build step (executed on the agent host, not in a container).
	Type         string `yaml:"type,omitempty" json:"type,omitempty"`             // "" (container step) | "docker_build" | "k8s_canary" | "k8s_blue_green"
	Dockerfile   string `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"` // docker_build: default "Dockerfile"
	BuildContext string `yaml:"context,omitempty" json:"context,omitempty"`       // docker_build: default "." (agent's CWD)
	Push         bool   `yaml:"push,omitempty" json:"push,omitempty"`             // docker_build: default false

	// P7⑤: k8s_canary / k8s_blue_green CD steps (executed on the scheduler
	// side, never dispatched to an agent; the scheduler drives the pkg/cd
	// release state machine for the step's strategy).
	K8sContext          string `yaml:"k8s_context,omitempty" json:"k8s_context,omitempty"`
	Namespace           string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	Deployment          string `yaml:"deployment,omitempty" json:"deployment,omitempty"`
	CanaryWeight        int    `yaml:"canary_weight,omitempty" json:"canary_weight,omitempty"`                 // 1..100, default 10 (informational in v1)
	CanaryProbeFailures int    `yaml:"canary_probe_failures,omitempty" json:"canary_probe_failures,omitempty"` // 0 → pkg/cd default
	CanaryTimeout       int    `yaml:"canary_timeout,omitempty" json:"canary_timeout,omitempty"`               // seconds; 0 → pkg/cd default
}

// PipelineSpec is the "pipeline" block of the document.
type PipelineSpec struct {
	Name        string            `yaml:"name" json:"name"` // required; ≤128
	Trigger     []Trigger         `yaml:"trigger,omitempty" json:"trigger,omitempty"`
	Concurrency int               `yaml:"concurrency,omitempty" json:"concurrency,omitempty"` // 1..100
	Env         map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets     []string          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// P7⑦: notification endpoints for run terminal states and canary rollback.
	Notifications []Notification `yaml:"notifications,omitempty" json:"notifications,omitempty"`
	Steps         []StepDef      `yaml:"steps" json:"steps"` // required, non-empty
}

// Pipeline is a fully parsed, validated flowstallion.yaml document.
type Pipeline struct {
	Version  int          `yaml:"version" json:"version"` // must be 1
	Pipeline PipelineSpec `yaml:"pipeline" json:"pipeline"`
}

// ---------------------------------------------------------------------------
// Wire types (pointers distinguish "omitted" from "explicit zero")
// ---------------------------------------------------------------------------

type wireTrigger struct {
	Event    string   `yaml:"event"`
	Branches []string `yaml:"branches"`
	Cron     *string  `yaml:"cron"`
}

type wireStep struct {
	ID           string            `yaml:"id"`
	Image        string            `yaml:"image"`
	Commands     []string          `yaml:"commands"`
	Needs        []string          `yaml:"needs"`
	Env          map[string]string `yaml:"env"`
	Timeout      *int              `yaml:"timeout"`
	Type         *string           `yaml:"type"`
	Dockerfile   *string           `yaml:"dockerfile"`
	BuildContext *string           `yaml:"context"`
	Push         *bool             `yaml:"push"`

	// P7⑤: k8s_canary / k8s_blue_green step fields.
	K8sContext *string         `yaml:"k8s_context"`
	Namespace  *string         `yaml:"namespace"`
	Deployment *string         `yaml:"deployment"`
	Canary     *wireCanaryOpts `yaml:"canary"`
}

// wireCanaryOpts is the CD step's `canary` block (k8s_canary /
// k8s_blue_green, P7⑤). Pointers distinguish "omitted" (→ pkg/cd defaults)
// from explicit values.
type wireCanaryOpts struct {
	Weight        *int `yaml:"weight"`
	ProbeFailures *int `yaml:"probe_failures"`
	Timeout       *int `yaml:"timeout"`
}

type wireSpec struct {
	Name        string            `yaml:"name"`
	Trigger     []wireTrigger     `yaml:"trigger"`
	Concurrency *int              `yaml:"concurrency"`
	Env         map[string]string `yaml:"env"`
	Secrets     []string          `yaml:"secrets"`
	// P7⑦: notification list; decoded as-is, validated in validateSpec.
	Notifications []Notification `yaml:"notifications"`
	Steps         []wireStep     `yaml:"steps"`
}

// ---------------------------------------------------------------------------
// ParseYAML
// ---------------------------------------------------------------------------

// ParseYAML parses and fully validates a flowstallion.yaml document.
//
// On success the returned Pipeline has step.Timeout normalised: omitted
// timeouts become DefaultStepTimeout.
//
// On any validation failure a single error is returned that aggregates
// every problem found. Each component message carries a field path
// (e.g. "pipeline.steps[1].id: ..."). Callers can enumerate individual
// problems via errors.Unwrap (the aggregated error implements
// Unwrap() []error).
func ParseYAML(data []byte) (Pipeline, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return Pipeline{}, fmt.Errorf("yaml: %s", oneLine(err.Error()))
	}

	doc := root
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return Pipeline{}, joinErrors([]string{
				"version: required (must be 1)",
				"pipeline: required",
			})
		}
		doc = *doc.Content[0]
	}

	if doc.Kind != yaml.MappingNode {
		return Pipeline{}, errors.New("document: top level must be a mapping with 'version' and 'pipeline'")
	}

	// Walk the top-level mapping once to locate 'version' and 'pipeline'.
	var versionNode, pipelineNode *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i]
		switch key.Value {
		case "version":
			versionNode = doc.Content[i+1]
		case "pipeline":
			pipelineNode = doc.Content[i+1]
		}
	}

	var errs []string

	// --- version -----------------------------------------------------------
	var version int
	switch {
	case versionNode == nil:
		errs = append(errs, "version: required (must be 1)")
	case decodeInt(versionNode, &version):
		errs = append(errs, "version: must be an integer")
	case version != 1:
		errs = append(errs, fmt.Sprintf("version: must be 1 (got %d)", version))
	}

	// --- pipeline block ----------------------------------------------------
	if pipelineNode == nil {
		errs = append(errs, "pipeline: required")
		return Pipeline{}, joinErrors(errs)
	}

	var spec wireSpec
	if err := pipelineNode.Decode(&spec); err != nil {
		errs = append(errs, fmt.Sprintf("pipeline: must be a mapping (%s)", oneLine(err.Error())))
		return Pipeline{}, joinErrors(errs)
	}

	errs = append(errs, validateSpec(spec)...)

	return buildPipeline(version, spec), joinErrors(errs)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// validateSpec returns one message per problem found in spec, each prefixed
// with its field path. An empty slice means the spec is fully valid.
func validateSpec(spec wireSpec) []string {
	var errs []string

	// --- pipeline.name -----------------------------------------------------
	switch {
	case spec.Name == "":
		errs = append(errs, "pipeline.name: required")
	case !pipelineNamePattern.MatchString(spec.Name):
		errs = append(errs, fmt.Sprintf("pipeline.name: must match %s (got %q, %d chars)",
			pipelineNamePattern.String(), spec.Name, len(spec.Name)))
	}

	// --- pipeline.trigger --------------------------------------------------
	for i, tr := range spec.Trigger {
		p := fmt.Sprintf("pipeline.trigger[%d]", i)

		if !validTriggerEvents[tr.Event] {
			errs = append(errs, p+".event: must be one of push, pull_request, schedule, manual (got "+quote(tr.Event)+")")
		}

		for j, b := range tr.Branches {
			if len(b) > MaxBranchLength {
				errs = append(errs, fmt.Sprintf("%s.branches[%d]: must be at most %d characters (got %d)",
					p, j, MaxBranchLength, len(b)))
			}
		}

		switch {
		case tr.Cron != nil:
			cron := *tr.Cron
			if cron == "" {
				errs = append(errs, p+".cron: must be non-empty")
			} else if len(cron) > MaxCronLength {
				errs = append(errs, fmt.Sprintf("%s.cron: must be at most %d characters (got %d)",
					p, MaxCronLength, len(cron)))
			}
			if tr.Event != "schedule" {
				errs = append(errs, p+".cron: only allowed when event is schedule")
			}
		case tr.Event == "schedule":
			errs = append(errs, p+".cron: required when event is schedule")
		}
	}

	// --- pipeline.concurrency ----------------------------------------------
	if spec.Concurrency != nil {
		c := *spec.Concurrency
		if c < MinConcurrency || c > MaxConcurrency {
			errs = append(errs, fmt.Sprintf("pipeline.concurrency: must be between %d and %d (got %d)",
				MinConcurrency, MaxConcurrency, c))
		}
	}

	// --- pipeline.secrets ---------------------------------------------------
	for i, s := range spec.Secrets {
		if !secretNamePattern.MatchString(s) || len(s) > MaxSecretNameLength {
			errs = append(errs, fmt.Sprintf("pipeline.secrets[%d]: must match %s and be at most %d characters (got %q, %d chars)",
				i, secretNamePattern.String(), MaxSecretNameLength, s, len(s)))
		}
	}

	// --- pipeline.notifications (P7⑦) ---------------------------------------
	if len(spec.Notifications) > MaxNotifications {
		errs = append(errs, fmt.Sprintf("pipeline.notifications: at most %d entries (got %d)",
			MaxNotifications, len(spec.Notifications)))
	}
	for i, nt := range spec.Notifications {
		p := fmt.Sprintf("pipeline.notifications[%d]", i)

		if !validNotificationTypes[nt.Type] {
			errs = append(errs, fmt.Sprintf("%s.type: must be one of webhook (got %q)", p, nt.Type))
		}

		switch {
		case nt.URL == "":
			errs = append(errs, p+".url: required")
		case len(nt.URL) > MaxNotificationURLLength:
			errs = append(errs, fmt.Sprintf("%s.url: must be at most %d characters (got %d)",
				p, MaxNotificationURLLength, len(nt.URL)))
		default:
			u, err := url.Parse(nt.URL)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s.url: invalid URL (%s)", p, oneLine(err.Error())))
			} else if u.Scheme != "http" && u.Scheme != "https" {
				errs = append(errs, fmt.Sprintf("%s.url: must be http or https (got %q)", p, u.Scheme))
			} else if u.Host == "" {
				errs = append(errs, p+".url: must include a host")
			}
		}
	}

	// --- pipeline.steps -----------------------------------------------------
	if len(spec.Steps) == 0 {
		errs = append(errs, "pipeline.steps: required (non-empty list)")
		return errs
	}

	// First-appearance index for each non-empty id (definition order).
	firstIndex := make(map[string]int, len(spec.Steps))
	var idOrder []string
	for i, st := range spec.Steps {
		if st.ID != "" {
			if _, seen := firstIndex[st.ID]; !seen {
				firstIndex[st.ID] = i
				idOrder = append(idOrder, st.ID)
			}
		}
	}

	for i, st := range spec.Steps {
		p := fmt.Sprintf("pipeline.steps[%d]", i)

		// type — closed set (P7④: "docker_build"; P7⑤: "k8s_canary";
		// plus "k8s_blue_green", the second CD release strategy).
		isBuild, isCanary, isBlueGreen := false, false, false
		if st.Type != nil {
			switch *st.Type {
			case "":
				// same as omitted
			case "docker_build":
				isBuild = true
			case "k8s_canary":
				isCanary = true
			case "k8s_blue_green":
				isBlueGreen = true
			default:
				errs = append(errs, fmt.Sprintf("%s.type: must be empty or one of %q, %q, %q (got %q)",
					p, "docker_build", "k8s_canary", "k8s_blue_green", *st.Type))
			}
		}
		isCD := isCanary || isBlueGreen

		// id
		switch {
		case st.ID == "":
			errs = append(errs, p+".id: required")
		case !stepIDPattern.MatchString(st.ID):
			errs = append(errs, fmt.Sprintf("%s.id: must match %s (got %q, %d chars)",
				p, stepIDPattern.String(), st.ID, len(st.ID)))
		default:
			if first, dup := firstIndex[st.ID]; dup && first != i {
				errs = append(errs, fmt.Sprintf("%s.id: duplicate id %q (first defined at pipeline.steps[%d].id)",
					p, st.ID, first))
			}
		}

		// image — reuse the closed-set pattern from steps.go; docker_build may
		// carry {{sha}}/{{branch}}/{{ts}} tag templates
		switch {
		case st.Image == "":
			errs = append(errs, p+".image: required")
		case isBuild && !validImageTemplate(st.Image):
			errs = append(errs, fmt.Sprintf("%s.image: invalid docker_build target image %q "+
				"(allowed: %s characters plus {{sha}} / {{branch}} / {{ts}})",
				p, st.Image, stepImagePattern.String()))
		case !isBuild && !stepImagePattern.MatchString(st.Image):
			errs = append(errs, fmt.Sprintf("%s.image: must match %s",
				p, stepImagePattern.String()))
		}

		// commands — container steps require them; docker_build and the CD
		// steps (k8s_canary / k8s_blue_green) forbid them (neither is a
		// container shell step).
		if isBuild || isCD {
			if len(st.Commands) > 0 {
				errs = append(errs, fmt.Sprintf("%s.commands: not allowed on %s steps",
					p, *st.Type))
			}
		} else if len(st.Commands) == 0 {
			errs = append(errs, p+".commands: required (non-empty list)")
		} else {
			for j, c := range st.Commands {
				switch {
				case c == "":
					errs = append(errs, fmt.Sprintf("%s.commands[%d]: must be non-empty", p, j))
				case len(c) > MaxCommandLength:
					errs = append(errs, fmt.Sprintf("%s.commands[%d]: must be at most %d characters (got %d)",
						p, j, MaxCommandLength, len(c)))
				}
			}
		}

		// docker_build-only path fields (security baseline §6: no traversal)
		if isBuild {
			if st.Dockerfile != nil {
				if err := checkDockerPath(*st.Dockerfile); err != nil {
					errs = append(errs, fmt.Sprintf("%s.dockerfile: %v", p, err))
				}
			}
			if st.BuildContext != nil {
				if err := checkDockerPath(*st.BuildContext); err != nil {
					errs = append(errs, fmt.Sprintf("%s.context: %v", p, err))
				}
			}
		}

		// CD-step-only fields (k8s_canary / k8s_blue_green; executed on the
		// scheduler side).
		if isCD {
			if st.Namespace == nil || *st.Namespace == "" {
				errs = append(errs, fmt.Sprintf("%s.namespace: required for %s steps", p, *st.Type))
			} else if !k8sNamePattern.MatchString(*st.Namespace) {
				errs = append(errs, fmt.Sprintf("%s.namespace: must match %s (got %q)",
					p, k8sNamePattern.String(), *st.Namespace))
			}
			if st.Deployment == nil || *st.Deployment == "" {
				errs = append(errs, fmt.Sprintf("%s.deployment: required for %s steps", p, *st.Type))
			} else if !k8sNamePattern.MatchString(*st.Deployment) {
				errs = append(errs, fmt.Sprintf("%s.deployment: must match %s (got %q)",
					p, k8sNamePattern.String(), *st.Deployment))
			} else {
				// The alternate object name (<deployment><strategy suffix>)
				// must fit K8s' 63-char object-name limit (RFC 1123).
				suffix := k8sAltSuffixCanary
				if isBlueGreen {
					suffix = k8sAltSuffixBlueGreen
				}
				if l := len(*st.Deployment) + len(suffix); l > 63 {
					errs = append(errs, fmt.Sprintf("%s.deployment: %q + %q = %d chars, exceeds K8s 63-char object-name limit",
						p, *st.Deployment, suffix, l))
				}
			}
			if st.K8sContext != nil && *st.K8sContext != "" && !k8sContextPattern.MatchString(*st.K8sContext) {
				errs = append(errs, fmt.Sprintf("%s.k8s_context: must match %s (got %q)",
					p, k8sContextPattern.String(), *st.K8sContext))
			}
			if st.Canary != nil {
				if st.Canary.Weight != nil &&
					(*st.Canary.Weight < MinCanaryWeight || *st.Canary.Weight > MaxCanaryWeight) {
					errs = append(errs, fmt.Sprintf("%s.canary.weight: must be between %d and %d (got %d)",
						p, MinCanaryWeight, MaxCanaryWeight, *st.Canary.Weight))
				}
				if st.Canary.ProbeFailures != nil && *st.Canary.ProbeFailures < 1 {
					errs = append(errs, fmt.Sprintf("%s.canary.probe_failures: must be ≥ 1 (got %d)",
						p, *st.Canary.ProbeFailures))
				}
				if st.Canary.Timeout != nil {
					to := *st.Canary.Timeout
					if to < MinStepTimeout || to > MaxStepTimeout {
						errs = append(errs, fmt.Sprintf("%s.canary.timeout: must be between %d and %d seconds (got %d)",
							p, MinStepTimeout, MaxStepTimeout, to))
					}
				}
			}
		} else if st.K8sContext != nil || st.Namespace != nil || st.Deployment != nil || st.Canary != nil {
			errs = append(errs, p+": k8s_context/namespace/deployment/canary are only allowed on k8s_canary / k8s_blue_green steps")
		}

		// timeout
		if st.Timeout != nil {
			t := *st.Timeout
			if t < MinStepTimeout || t > MaxStepTimeout {
				errs = append(errs, fmt.Sprintf("%s.timeout: must be between %d and %d seconds (got %d)",
					p, MinStepTimeout, MaxStepTimeout, t))
			}
		}
	}

	// --- needs: existence + DAG ---------------------------------------------
	for i, st := range spec.Steps {
		p := fmt.Sprintf("pipeline.steps[%d]", i)
		for _, n := range st.Needs {
			if _, ok := firstIndex[n]; !ok {
				errs = append(errs, fmt.Sprintf("%s.needs: unknown step id %q", p, n))
			}
		}
	}

	if cycle := findNeedsCycle(idOrder, firstIndex, spec.Steps); cycle != nil {
		errs = append(errs, "pipeline.steps: needs graph contains a cycle: "+strings.Join(cycle, " -> "))
	}

	return errs
}

// ---------------------------------------------------------------------------
// DAG cycle detection (iterative DFS, deterministic by definition order)
// ---------------------------------------------------------------------------

// findNeedsCycle returns a cycle path (e.g. ["a","b","a"]) if the needs
// graph has a cycle, including self-loops. It returns nil when the graph
// is a valid DAG. Nodes are traversed in first-appearance order so the
// reported cycle is deterministic.
func findNeedsCycle(idOrder []string, firstIndex map[string]int, steps []wireStep) []string {
	// Build adjacency: only edges whose target is a known id.
	adj := make(map[string][]string, len(steps))
	for i, st := range steps {
		if st.ID == "" || firstIndex[st.ID] != i {
			continue // skip empty ids and duplicate definitions
		}
		for _, n := range st.Needs {
			if _, ok := firstIndex[n]; ok {
				adj[st.ID] = append(adj[st.ID], n)
			}
		}
	}

	const (
		white = 0 // unvisited
		gray  = 1 // on current DFS path
		black = 2 // fully explored
	)
	color := make(map[string]int, len(idOrder))
	var path []string

	type frame struct {
		node string
		next int
	}
	var stack []frame

	for _, start := range idOrder {
		if color[start] != white {
			continue
		}
		color[start] = gray
		stack = append(stack, frame{start, 0})
		path = append(path, start)

		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.next < len(adj[top.node]) {
				v := adj[top.node][top.next]
				top.next++
				switch color[v] {
				case gray:
					// Back edge: cycle is path[pos(v)] … path[len-1] → v
					for pos := range path {
						if path[pos] == v {
							cycle := make([]string, 0, len(path)-pos+1)
							cycle = append(cycle, path[pos:]...)
							cycle = append(cycle, v)
							return cycle
						}
					}
					// unreachable: v is gray but not on path
					return []string{v, v}
				case white:
					color[v] = gray
					stack = append(stack, frame{v, 0})
					path = append(path, v)
				}
			} else {
				color[top.node] = black
				stack = stack[:len(stack)-1]
				path = path[:len(path)-1]
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildPipeline converts the decoded wire form into the exported Pipeline,
// applying defaults (omitted step timeout → DefaultStepTimeout).
func buildPipeline(version int, spec wireSpec) Pipeline {
	steps := make([]StepDef, 0, len(spec.Steps))
	for _, st := range spec.Steps {
		timeout := DefaultStepTimeout
		if st.Timeout != nil {
			timeout = *st.Timeout
		}
		stType := ""
		if st.Type != nil {
			stType = *st.Type
		}
		dockerfile := "Dockerfile"
		if st.Dockerfile != nil && *st.Dockerfile != "" {
			dockerfile = *st.Dockerfile
		}
		buildCtx := "."
		if st.BuildContext != nil && *st.BuildContext != "" {
			buildCtx = *st.BuildContext
		}
		push := false
		if st.Push != nil {
			push = *st.Push
		}
		k8sContext, ns, deploy := "", "", ""
		if st.K8sContext != nil {
			k8sContext = *st.K8sContext
		}
		if st.Namespace != nil {
			ns = *st.Namespace
		}
		if st.Deployment != nil {
			deploy = *st.Deployment
		}
		canaryWeight := DefaultCanaryWeight
		canaryProbeFailures, canaryTimeout := 0, 0 // 0 → pkg/cd defaults (P7⑤)
		if st.Canary != nil {
			if st.Canary.Weight != nil {
				canaryWeight = *st.Canary.Weight
			}
			if st.Canary.ProbeFailures != nil {
				canaryProbeFailures = *st.Canary.ProbeFailures
			}
			if st.Canary.Timeout != nil {
				canaryTimeout = *st.Canary.Timeout
			}
		}
		steps = append(steps, StepDef{
			ID:                  st.ID,
			Image:               st.Image,
			Commands:            st.Commands,
			Needs:               st.Needs,
			Env:                 st.Env,
			Timeout:             timeout,
			Type:                stType,
			Dockerfile:          dockerfile,
			BuildContext:        buildCtx,
			Push:                push,
			K8sContext:          k8sContext,
			Namespace:           ns,
			Deployment:          deploy,
			CanaryWeight:        canaryWeight,
			CanaryProbeFailures: canaryProbeFailures,
			CanaryTimeout:       canaryTimeout,
		})
	}

	triggers := make([]Trigger, 0, len(spec.Trigger))
	for _, tr := range spec.Trigger {
		cron := ""
		if tr.Cron != nil {
			cron = *tr.Cron
		}
		triggers = append(triggers, Trigger{Event: tr.Event, Branches: tr.Branches, Cron: cron})
	}

	concurrency := 0
	if spec.Concurrency != nil {
		concurrency = *spec.Concurrency
	}

	return Pipeline{
		Version: version,
		Pipeline: PipelineSpec{
			Name:          spec.Name,
			Trigger:       triggers,
			Concurrency:   concurrency,
			Env:           spec.Env,
			Secrets:       spec.Secrets,
			Notifications: spec.Notifications,
			Steps:         steps,
		},
	}
}

// imageTemplatePlaceholders are the allowed tag templates in a
// docker_build target image (expanded by the scheduler at run time, P7④).
var imageTemplatePlaceholders = []string{"{{sha}}", "{{branch}}", "{{ts}}"}

// validImageTemplate reports whether s is a legal docker_build target image:
// the template must contain at least one non-placeholder character and,
// after substituting each allowed {{placeholder}} with a neutral valid
// character, the result must match stepImagePattern.
func validImageTemplate(s string) bool {
	// Reject templates composed solely of placeholders (no repo/registry).
	stripped := s
	for _, pl := range imageTemplatePlaceholders {
		stripped = strings.ReplaceAll(stripped, pl, "")
	}
	if stripped == "" {
		return false
	}
	replaced := s
	for _, pl := range imageTemplatePlaceholders {
		replaced = strings.ReplaceAll(replaced, pl, "x")
	}
	if strings.Contains(replaced, "{{") {
		return false
	}
	return stepImagePattern.MatchString(replaced)
}

// checkDockerPath validates a docker build path (dockerfile or context):
// non-empty, ≤256 chars, relative (no leading "/"), no empty or ".."
// segments, and a safe character set (alnum, '.', '_', '-', '/').
func checkDockerPath(s string) error {
	if len(s) == 0 || len(s) > 256 {
		return errors.New("must be 1-256 characters")
	}
	if strings.HasPrefix(s, "/") {
		return errors.New("must be a relative path")
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == ".." {
			return errors.New(`must not contain empty or ".." segments`)
		}
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '/':
		default:
			return fmt.Errorf("unsupported character %q", r)
		}
	}
	return nil
}

// joinErrors aggregates field errors into a single error. Each message
// becomes an independent joined error so callers can enumerate them
// (e.g. via errors.Unwrap). An empty or nil slice returns nil.
func joinErrors(msgs []string) error {
	if len(msgs) == 0 {
		return nil
	}
	errs := make([]error, 0, len(msgs))
	for _, m := range msgs {
		if m != "" {
			errs = append(errs, errors.New(m))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return errors.Join(errs...)
}

// oneLine collapses a (possibly multi-line) string to a single line.
func oneLine(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
}

// decodeInt decodes a yaml.Node into an int. Returns true if the node
// cannot be interpreted as an integer (type mismatch, out of range, etc.).
func decodeInt(n *yaml.Node, out *int) bool {
	return n.Decode(out) != nil
}

// quote wraps s in double quotes for safe display in error messages.
func quote(s string) string {
	return `"` + s + `"`
}
