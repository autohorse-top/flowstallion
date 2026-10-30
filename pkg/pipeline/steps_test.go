package pipeline

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateStep(t *testing.T) {
	nameAtLimit := strings.Repeat("a", 64)
	nameTooLong := strings.Repeat("a", 65)
	imageTooLong := "g" + strings.Repeat("a", 512) // 513 chars total
	cmdAtLimit := strings.Repeat("x", MaxCommandLength)
	cmdTooLong := strings.Repeat("x", MaxCommandLength+1)

	cases := []struct {
		name    string
		step    Step
		wantErr error // nil means the step must be accepted.
	}{
		{
			name: "valid step",
			step: Step{Name: "build", Image: "golang:1.22", Commands: []string{"go build ./..."}},
		},
		{
			name: "name with hyphen and underscore is valid",
			step: Step{Name: "my-step_01", Image: "alpine", Commands: []string{"echo hi"}},
		},
		{
			name: "name at 64 chars is valid",
			step: Step{Name: nameAtLimit, Image: "alpine", Commands: []string{"echo hi"}},
		},
		{
			name: "registry image with path and tag is valid",
			step: Step{Name: "scan", Image: "ghcr.io/org/flowstallion/trivy:1.2", Commands: []string{"trivy fs ."}},
		},
		{
			name:    "empty name",
			step:    Step{Name: "", Image: "alpine", Commands: []string{"echo hi"}},
			wantErr: ErrInvalidStepName,
		},
		{
			name:    "name starts with digit",
			step:    Step{Name: "1build", Image: "alpine", Commands: []string{"echo hi"}},
			wantErr: ErrInvalidStepName,
		},
		{
			name:    "name too long",
			step:    Step{Name: nameTooLong, Image: "alpine", Commands: []string{"echo hi"}},
			wantErr: ErrInvalidStepName,
		},
		{
			name:    "empty image",
			step:    Step{Name: "build", Image: "", Commands: []string{"go build ./..."}},
			wantErr: ErrInvalidStepImage,
		},
		{
			name:    "image with embedded newline",
			step:    Step{Name: "build", Image: "alpine\n-malicious", Commands: []string{"echo hi"}},
			wantErr: ErrInvalidStepImage,
		},
		{
			name:    "image with space",
			step:    Step{Name: "build", Image: "alpine latest", Commands: []string{"echo hi"}},
			wantErr: ErrInvalidStepImage,
		},
		{
			name:    "image too long",
			step:    Step{Name: "build", Image: imageTooLong, Commands: []string{"echo hi"}},
			wantErr: ErrInvalidStepImage,
		},
		{
			name:    "empty commands",
			step:    Step{Name: "build", Image: "golang:1.22", Commands: nil},
			wantErr: ErrEmptyCommands,
		},
		{
			name:    "empty command string",
			step:    Step{Name: "build", Image: "alpine", Commands: []string{""}},
			wantErr: ErrInvalidCommand,
		},
		{
			name:    "command too long",
			step:    Step{Name: "build", Image: "alpine", Commands: []string{cmdTooLong}},
			wantErr: ErrInvalidCommand,
		},
		{
			name: "command at 4096 chars is valid",
			step: Step{Name: "build", Image: "alpine", Commands: []string{cmdAtLimit}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStep(tc.step)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateStep() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateStep() error = %v, want sentinel %v", err, tc.wantErr)
			}
		})
	}
}
