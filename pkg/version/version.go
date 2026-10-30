// Package version holds the FlowStallion release version.
package version

// Version is the semantic version of this build.
const Version = "0.0.1"

// String returns the human-readable version banner,
// e.g. "flowstallion version 0.0.1".
func String() string {
	return "flowstallion version " + Version
}
