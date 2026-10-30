// Command flowstallion is the FlowStallion command-line interface.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/flowstallion/flowstallion/pkg/pipeline"
	"github.com/flowstallion/flowstallion/pkg/version"
)

func usage(w io.Writer) {
	fmt.Fprint(w, `FlowStallion — open-source autonomous SDLC/CI-CD platform

Usage:
  flowstallion <command> [args] [flags]

Commands:
  version     print the FlowStallion version
  validate    validate a flowstallion.yaml file
  login       save the scheduler URL; with -u/-p authenticate and save the session token
  create      upload/create a pipeline from a flowstallion.yaml file
  trigger     trigger a pipeline run
  status      show recent runs, or one run with its steps
  logs        show logs for a run step
  scan        run a security scan and store it on a run (--tool trivy|gitleaks|semgrep)
  approve     approve a policy-held (pending_approval) run
  reject      reject a policy-held (pending_approval) run (--reason optional)
  canary      show the canary release for a run, or roll it back:
                flowstallion canary <run-id> [rollback]
  cost        print a cost table from the shared ledger (--by pr|team --source llm|cloud)
  audit       list audit-log events (--limit N --actor A --action X --after ID)
  users       list users (admin)
  user add    create a user (admin)
  user del    delete a user (admin)
  secret set  set/update a secret value (admin)
  secret list list stored secrets (admin)
  secret rm   delete a secret (admin)
  help        show this help

Environment:
  FLOWSTALLION_SERVER  scheduler base URL (overrides saved config)
  FLOWSTALLION_TOKEN   session token (overrides saved token)
`)
}

// extractFlags moves known flag tokens (and their values) ahead of
// positional args so flag.Parse sees them. Go's flag package stops parsing
// at the first non-flag argument, so "flowstallion logs 42 --step build" would
// otherwise treat "--step" as a positional arg.
func extractFlags(args []string, known []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		isFlag := false
		for _, k := range known {
			if a == k || strings.HasPrefix(a, k+"=") {
				isFlag = true
				break
			}
		}
		if !isFlag {
			rest = append(rest, a)
			continue
		}
		flags = append(flags, a)
		if !strings.Contains(a, "=") {
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "-") {
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, rest...)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(1)
	}
	switch args[0] {
	case "version":
		fmt.Println(version.String())
	case "validate":
		runValidate(args[1:])
	case "login":
		runLogin(args[1:])
	case "create":
		runCreate(args[1:])
	case "trigger":
		runTrigger(args[1:])
	case "status":
		runStatus(args[1:])
	case "logs":
		runLogs(args[1:])
	case "scan":
		runScan(args[1:])
	case "approve":
		runApprove(args[1:])
	case "reject":
		runReject(args[1:])
	case "canary":
		runCanary(args[1:])
	case "cost":
		runCost(args[1:])
	case "audit":
		runAudit(args[1:])
	case "users":
		runUsers(args[1:])
	case "user":
		runUser(args[1:])
	case "secret":
		runSecret(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "flowstallion: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// validate (unchanged)
// ---------------------------------------------------------------------------

func runValidate(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: flowstallion validate <file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: cannot read %s: %v\n", args[0], err)
		os.Exit(1)
	}

	p, err := pipeline.ParseYAML(data)
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			if line != "" {
				fmt.Fprintln(os.Stderr, line)
			}
		}
		os.Exit(1)
	}

	fmt.Printf("OK: %s (%d steps)\n", p.Pipeline.Name, len(p.Pipeline.Steps))
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	user := fs.String("u", "", "username to authenticate")
	pass := fs.String("p", "", "password (prompted when -u is given without -p)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion login <scheduler-url> [-u user] [-p pass]")
	}
	args = extractFlags(args, []string{"-u", "-p", "--u", "--p"})
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	url := fs.Arg(0)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Fprintf(os.Stderr, "flowstallion: server URL must start with http:// or https:// (got %q)\n", url)
		os.Exit(1)
	}
	cfg := config{Server: url}
	if *user != "" {
		if *pass == "" {
			fmt.Fprint(os.Stderr, "Password: ")
			if _, err := fmt.Scanln(&*pass); err != nil {
				fmt.Fprintf(os.Stderr, "flowstallion: cannot read password: %v\n", err)
				os.Exit(1)
			}
		}
		var out struct {
			Token    string `json:"token"`
			Username string `json:"username"`
		}
		if err := newClient(url, "").doJSON("POST", "/api/auth/login",
			map[string]string{"username": *user, "password": *pass}, &out); err != nil {
			if ae, ok := err.(*apiError); ok && ae.Status == http.StatusForbidden {
				fmt.Fprintln(os.Stderr, "flowstallion: authentication is disabled on the server; saving server URL only")
			} else {
				fatalAPI(err)
			}
		} else {
			cfg.Token = out.Token
			cfg.User = out.Username
		}
	}
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: %v\n", err)
		os.Exit(1)
	}
	p, _ := configPath()
	if cfg.Token != "" {
		fmt.Printf("Authenticated as %s on %s (config: %s)\n", cfg.User, url, p)
	} else {
		fmt.Printf("Logged in to %s (config: %s)\n", url, p)
	}
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion create <flowstallion.yaml>")
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: cannot read %s: %v\n", fs.Arg(0), err)
		os.Exit(1)
	}
	p, err := pipeline.ParseYAML(data)
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			if line != "" {
				fmt.Fprintln(os.Stderr, line)
			}
		}
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	var out pipelineJSON
	if err := c.doJSON("POST", "/api/pipelines",
		map[string]string{"name": p.Pipeline.Name, "yaml": string(data)}, &out); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("Pipeline %q created (id %d, %d steps)\n", out.Name, out.ID, len(p.Pipeline.Steps))
}

// ---------------------------------------------------------------------------
// trigger
// ---------------------------------------------------------------------------

func runTrigger(args []string) {
	fs := flag.NewFlagSet("trigger", flag.ExitOnError)
	triggerType := fs.String("trigger", "manual", "trigger type (manual|push|pull_request|schedule)")
	ref := fs.String("ref", "", "source ref (branch/tag)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion trigger <pipeline-name> [--trigger manual] [--ref <branch>]")
	}
	args = extractFlags(args, []string{"--trigger", "--ref"})
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	body := map[string]string{"trigger": *triggerType, "source_ref": *ref}
	var out struct {
		RunID int64 `json:"run_id"`
	}
	if err := c.doJSON("POST", "/api/pipelines/"+name+"/trigger", body, &out); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("Run #%d started (pipeline: %s)\n", out.RunID, name)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	limit := fs.Int("limit", 20, "max runs to list (without a run id)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion status [run-id] [--limit N]")
	}
	args = extractFlags(args, []string{"--limit"})
	fs.Parse(args)
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}

	if fs.NArg() == 1 {
		id, perr := strconv.ParseInt(fs.Arg(0), 10, 64)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "flowstallion: run id must be an integer (got %q)\n", fs.Arg(0))
			os.Exit(1)
		}
		var out struct {
			Run   runJSON    `json:"run"`
			Steps []stepJSON `json:"steps"`
		}
		if err := c.doJSON("GET", "/api/runs/"+strconv.FormatInt(id, 10), nil, &out); err != nil {
			fatalAPI(err)
		}
		r := out.Run
		fmt.Printf("Run #%d  %s  (pipeline %d, trigger %s%s)\n",
			r.ID, r.Status, r.PipelineID, r.Trigger, refSuffix(r.SourceRef))
		if r.StartedAt != "" {
			fmt.Printf("  started:  %s\n", r.StartedAt)
		}
		if r.FinishedAt != "" {
			fmt.Printf("  finished: %s\n", r.FinishedAt)
		}
		if r.RejectReason != "" {
			fmt.Printf("  rejected: %s\n", r.RejectReason)
		}
		for _, s := range out.Steps {
			ref := ""
			if s.FinishedAt != "" {
				ref = "  finished " + s.FinishedAt
			}
			fmt.Printf("  [%s] %s  (image: %s)%s\n", s.StepID, s.Status, s.Image, ref)
			for _, k := range sortedMapKeys(s.Outputs) {
				fmt.Printf("       output %s = %s\n", k, s.Outputs[k])
			}
		}
		return
	}

	// List recent runs.
	var runs []runJSON
	if err := c.doJSON("GET", fmt.Sprintf("/api/runs?limit=%d", *limit), nil, &runs); err != nil {
		fatalAPI(err)
	}
	if len(runs) == 0 {
		fmt.Println("No runs found.")
		return
	}
	fmt.Printf("%-6s %-14s %-10s %-12s %s\n", "ID", "STATUS", "PIPELINE", "TRIGGER", "STARTED")
	for _, r := range runs {
		fmt.Printf("%-6d %-14s %-10d %-12s %s\n", r.ID, r.Status, r.PipelineID, r.Trigger, r.StartedAt)
	}
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

func runLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	step := fs.String("step", "", "step id (required — logs are per-step)")
	since := fs.Int64("since", 0, "resume after this log sequence number")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion logs <run-id> --step <step-id> [--since <seq>]")
	}
	args = extractFlags(args, []string{"--step", "--since"})
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	runID, perr := strconv.ParseInt(fs.Arg(0), 10, 64)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "flowstallion: run id must be an integer (got %q)\n", fs.Arg(0))
		os.Exit(1)
	}
	if *step == "" {
		fmt.Fprintln(os.Stderr, "flowstallion: --step <step-id> is required")
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	q := fmt.Sprintf("/api/runs/%d/logs?step=%s&after=%d&limit=1000", runID, *step, *since)
	var out struct {
		Logs []logJSON `json:"logs"`
	}
	if err := c.doJSON("GET", q, nil, &out); err != nil {
		fatalAPI(err)
	}
	for _, l := range out.Logs {
		fmt.Printf("%s\n", l.Line)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// apiClient builds a client from FLOWSTALLION_SERVER / FLOWSTALLION_TOKEN (if set)
// or the saved login config. FLOWSTALLION_SERVER alone suffices: open-mode
// (no-auth) servers need no token, so the saved config is only consulted
// when the server env var is unset.
func apiClient() (*client, error) {
	server := os.Getenv("FLOWSTALLION_SERVER")
	token := os.Getenv("FLOWSTALLION_TOKEN")
	if server == "" {
		c, err := loadConfig()
		if err != nil {
			return nil, err
		}
		server = c.Server
		if token == "" {
			token = c.Token
		}
	}
	return newClient(server, token), nil
}

func refSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return " " + ref
}

// sortedMapKeys returns the keys of m in sorted order so CLI output is
// deterministic regardless of map iteration order.
func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fatalConfig(err error) {
	fmt.Fprintf(os.Stderr, "flowstallion: %v\n", err)
	os.Exit(1)
}

func fatalAPI(err error) {
	// 422 responses may carry a structured "problems" list — print it.
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 422 {
		var body struct {
			Error    string   `json:"error"`
			Problems []string `json:"problems"`
		}
		if json.Unmarshal([]byte(ae.Message), &body) == nil && len(body.Problems) > 0 {
			fmt.Fprintf(os.Stderr, "flowstallion: %s\n", body.Error)
			for _, p := range body.Problems {
				fmt.Fprintf(os.Stderr, "  - %s\n", p)
			}
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "flowstallion: %v\n", err)
	os.Exit(1)
}
