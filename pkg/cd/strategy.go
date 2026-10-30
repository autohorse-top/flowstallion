package cd

// Strategy abstracts a CD release strategy. Each strategy decides how the
// alternate (new-version) K8s objects are named and sized relative to the
// stable deployment; the state machine (Controller) is strategy-agnostic and
// drives whichever strategy the release row carries.
type Strategy interface {
	// ID is the persisted strategy identifier ("canary" | "blue_green").
	ID() string
	// AltName is the K8s object name of the alternate deployment/service,
	// derived from the stable name (the release's Name field).
	AltName(base string) string
	// AltReplicas is the replica count of the alternate deployment given
	// the stable deployment's replica count.
	AltReplicas(full int) int
}

// CanaryStrategy is the original isolated-canary strategy: a single-replica
// canary deployment alongside the full stable fleet; traffic switches by
// repointing the stable Service selector at the canary pods.
type CanaryStrategy struct{}

// BlueGreenStrategy is the blue-green strategy: a full-replica alternate
// environment ("blue" against the "green" stable fleet); the switch is a
// selector repoint of the stable Service at the alternate pods, and the
// stable deployment is deleted only after the switch succeeds.
type BlueGreenStrategy struct{}

var (
	canaryStrategy    = CanaryStrategy{}
	blueGreenStrategy = BlueGreenStrategy{}
)

func (CanaryStrategy) ID() string                 { return "canary" }
func (CanaryStrategy) AltName(base string) string { return base + "-canary" }
func (CanaryStrategy) AltReplicas(int) int        { return 1 }

func (BlueGreenStrategy) ID() string                 { return "blue_green" }
func (BlueGreenStrategy) AltName(base string) string { return base + "-alt" }
func (BlueGreenStrategy) AltReplicas(full int) int   { return full }

// StrategyFor resolves a persisted strategy identifier to its implementation.
// Empty or unknown identifiers fall back to the canary strategy (legacy
// default for rows predating the strategy column).
func StrategyFor(id string) Strategy {
	switch id {
	case blueGreenStrategy.ID():
		return blueGreenStrategy
	default:
		return canaryStrategy
	}
}

// AltName returns the strategy-specific alternate object name for a stable
// name and strategy identifier (package-level helper for callers that hold
// the strategy as a string rather than a Strategy value).
func AltName(base, strategyID string) string {
	return StrategyFor(strategyID).AltName(base)
}
