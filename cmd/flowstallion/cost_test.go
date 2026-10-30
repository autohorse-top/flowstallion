package main

import (
	"testing"

	"github.com/flowstallion/flowstallion/pkg/finops"
)

// TestResolveCostArgs is the flag-validation matrix for `flowstallion cost`.
func TestResolveCostArgs(t *testing.T) {
	cases := []struct {
		by, source string
		wantBy     string
		wantSrc    string
		wantErr    bool
	}{
		{"", "", "pr", "", false}, // defaults
		{"pr", "", "pr", "", false},
		{"team", "", "team", "", false},
		{"pr", "llm", "pr", "llm", false},
		{"team", "cloud", "team", "cloud", false},
		{"", "llm", "pr", "llm", false},
		{"foo", "", "", "", true},   // bad by
		{"pr", "web", "", "", true}, // bad source
		{"team", "web", "", "", true},
	}
	for _, tc := range cases {
		by, src, err := resolveCostArgs(tc.by, tc.source)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resolveCostArgs(%q, %q): err = nil, want error", tc.by, tc.source)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveCostArgs(%q, %q): unexpected error %v", tc.by, tc.source, err)
			continue
		}
		if by != tc.wantBy || src != tc.wantSrc {
			t.Errorf("resolveCostArgs(%q, %q) = (%q, %q), want (%q, %q)",
				tc.by, tc.source, by, src, tc.wantBy, tc.wantSrc)
		}
	}
}

func costRow(by string, key string, records int, prompt, completion, tokens int64, cost float64) finops.Row {
	return finops.Row{
		by:                  key,
		"records":           records,
		"prompt_tokens":     prompt,
		"completion_tokens": completion,
		"total_tokens":      tokens,
		"cost_usd":          cost,
	}
}

func costTotal(records int, prompt, completion, tokens int64, cost float64) map[string]any {
	return map[string]any{
		"records":           records,
		"prompt_tokens":     prompt,
		"completion_tokens": completion,
		"total_tokens":      tokens,
		"cost_usd":          cost,
	}
}

// TestFormatCostTable pins the exact table layout (header, row alignment,
// TOTAL row, zero-row case).
func TestFormatCostTable(t *testing.T) {
	t.Run("by pr with rows", func(t *testing.T) {
		rows := []finops.Row{
			costRow("pr", "101", 3, 100, 50, 150, 0.25),
			costRow("pr", "unknown", 1, 10, 5, 15, 0.01),
		}
		got := formatCostTable(rows, "pr", "", costTotal(4, 110, 55, 165, 0.26))
		want := "cost by pr (source: all)\n" +
			"KEY            RECORDS  PROMPT COMPLETION    TOTAL  COST_USD\n" +
			"101                  3     100        50      150    0.2500\n" +
			"unknown              1      10         5       15    0.0100\n" +
			"TOTAL                4     110        55      165    0.2600\n"
		if got != want {
			t.Fatalf("table mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
		}
	})

	t.Run("by team with source filter label", func(t *testing.T) {
		rows := []finops.Row{costRow("team", "platform", 2, 7, 3, 10, 0.1)}
		got := formatCostTable(rows, "team", "llm", costTotal(2, 7, 3, 10, 0.1))
		want := "cost by team (source: llm)\n" +
			"KEY            RECORDS  PROMPT COMPLETION    TOTAL  COST_USD\n" +
			"platform             2       7         3       10    0.1000\n" +
			"TOTAL                2       7         3       10    0.1000\n"
		if got != want {
			t.Fatalf("table mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
		}
	})

	t.Run("zero rows", func(t *testing.T) {
		got := formatCostTable(nil, "pr", "cloud", costTotal(0, 0, 0, 0, 0))
		want := "cost by pr (source: cloud)\n" +
			"KEY            RECORDS  PROMPT COMPLETION    TOTAL  COST_USD\n" +
			"(no cost records)\n"
		if got != want {
			t.Fatalf("zero-row table mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
		}
	})
}
