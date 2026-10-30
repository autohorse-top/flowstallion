// Package pipeline defines FlowStallion pipeline primitives.
package pipeline

import (
	"errors"
	"regexp"
)

// Step is a single executable unit of a pipeline: one container image
// with an ordered list of shell commands.
type Step struct {
	Name     string
	Image    string
	Commands []string
}

// MaxCommandLength is the maximum length of a single step command.
const MaxCommandLength = 4096

// Sentinel errors returned by ValidateStep.
var (
	// ErrInvalidStepName is returned when a step name does not match
	// the pattern ^[a-zA-Z][a-zA-Z0-9_-]{0,63}$ (64 characters max).
	ErrInvalidStepName = errors.New("pipeline: invalid step name: must match ^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")

	// ErrInvalidStepImage is returned when a step image is empty or
	// contains characters outside the safe reference character set.
	ErrInvalidStepImage = errors.New("pipeline: invalid step image: must match ^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,511}$")

	// ErrEmptyCommands is returned when a step has no commands.
	ErrEmptyCommands = errors.New("pipeline: step commands must be non-empty")

	// ErrInvalidCommand is returned when a command is empty or longer
	// than MaxCommandLength characters.
	ErrInvalidCommand = errors.New("pipeline: invalid command: must be non-empty and at most 4096 characters")
)

// stepNamePattern: a leading letter followed by up to 63 letters,
// digits, '_' or '-' (64 characters total).
var stepNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

// stepImagePattern: container image references (optional registry host,
// path, ':tag' or '@digest'). The character set is deliberately closed so
// user-supplied pipeline definitions cannot smuggle newlines, spaces or
// shell metacharacters into the image field (security baseline, AGENTS.md §6).
var stepImagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,511}$`)

// ValidateStep checks that s is a well-formed step. It returns one of
// the package sentinel errors on failure, or nil if the step is valid.
func ValidateStep(s Step) error {
	if !stepNamePattern.MatchString(s.Name) {
		return ErrInvalidStepName
	}
	if !stepImagePattern.MatchString(s.Image) {
		return ErrInvalidStepImage
	}
	if len(s.Commands) == 0 {
		return ErrEmptyCommands
	}
	for _, c := range s.Commands {
		if c == "" || len(c) > MaxCommandLength {
			return ErrInvalidCommand
		}
	}
	return nil
}
