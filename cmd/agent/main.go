// Command agent is the FlowStallion runner agent. It registers with a
// scheduler, polls for jobs, runs each step in a Docker container, and
// streams logs back over HTTP.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flowstallion/flowstallion/pkg/agent"
	"github.com/flowstallion/flowstallion/pkg/version"
)

func main() {
	var (
		server  = flag.String("server", defaultEnv("FLOWSTALLION_SERVER", "http://localhost:8080"), "scheduler base URL")
		name    = flag.String("name", defaultEnv("FLOWSTALLION_AGENT_NAME", defaultName()), "agent name registered with the scheduler")
		poll    = flag.Duration("poll", 500*time.Millisecond, "poll interval")
		token   = flag.String("token", defaultEnv("FLOWSTALLION_AGENT_TOKEN", ""), "scheduler machine token sent as X-Agent-Token (required when scheduler auth is on)")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	log.SetPrefix("agent: ")
	log.SetOutput(os.Stderr)
	flag.Parse()

	if *showVer {
		log.Println(version.String() + " (agent)")
		return
	}
	if *name == "" || len(*name) > 128 {
		log.Fatal("agent name must be 1-128 chars")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := &agent.Agent{
		Name:       *name,
		Server:     *server,
		Docker:     &agent.CLI{},
		Host:       &agent.HostCLI{}, // P7④: host-side docker build/push/login for docker_build steps
		Poll:       *poll,
		AgentToken: *token,
	}
	if err := a.Run(ctx); err != nil {
		log.Fatalf("%v", err)
	}
}

func defaultEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "agent"
	}
	return hostname
}
