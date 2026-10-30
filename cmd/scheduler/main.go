// Command scheduler runs the FlowStallion pipeline scheduler: an HTTP API
// (JSON + SSE) backed by SQLite, dispatching steps to runner agents.
//
// Usage:
//
//	flowstallion-scheduler [-db path] [-addr :8080]
//
// Environment:
//
//	FLOWSTALLION_DB               SQLite path (default "data/flowstallion.db")
//	FLOWSTALLION_ADDR             listen address (default ":8080")
//	FLOWSTALLION_AUTH             "on" enables AuthN/RBAC (default off = open)
//	FLOWSTALLION_SESSION_TTL      session lifetime, Go duration (default 168h)
//	FLOWSTALLION_AGENT_TOKEN      machine token for /api/agent/*; unset while
//	                           auth is on = agent endpoints open + warning
//	FLOWSTALLION_ADMIN_USERNAME   bootstrap admin (only when users table is empty)
//	FLOWSTALLION_ADMIN_PASSWORD   bootstrap admin password
//	FLOWSTALLION_SECRET_KEY       enable the secret vault (64 hex chars or base64
//	                           of a 32-byte key); ${NAME} env references in
//	                           pipelines are resolved from the encrypted store
//	FLOWSTALLION_COST_LEDGER      shared JSONL cost ledger path (default
//	                           ~/.flowstallion/cost-ledger.jsonl); read by
//	                           GET /api/cost for the /cost console page
//	FLOWSTALLION_KUBECTL_BIN      kubectl binary used by k8s_canary steps and
//	                           the canary background driver (default "kubectl")
//	FLOWSTALLION_WEB_BASE_URL     web console base URL (no trailing slash) used
//	                           for the "url" field of webhook notifications
//	                           (P7⑦); default derived from the listen address
//	FLOWSTALLION_LOG_RETENTION    log/canary-event retention policy (P7⑧):
//	                           "<n>d" purges rows older than n days,
//	                           "runs=<n>" keeps the newest n runs' logs;
//	                           unset = disabled, invalid value is logged
//	                           and ignored
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/flowstallion/flowstallion/pkg/api"
	"github.com/flowstallion/flowstallion/pkg/auth"
	"github.com/flowstallion/flowstallion/pkg/cd"
	"github.com/flowstallion/flowstallion/pkg/notify"
	"github.com/flowstallion/flowstallion/pkg/policy"
	"github.com/flowstallion/flowstallion/pkg/scheduler"
	"github.com/flowstallion/flowstallion/pkg/secret"
	"github.com/flowstallion/flowstallion/pkg/store"
	"github.com/flowstallion/flowstallion/pkg/web"
)

// bootstrapUserRe matches the same usernames the user-management API accepts.
var bootstrapUserRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

func main() {
	dbPath := flag.String("db", envOr("FLOWSTALLION_DB", "data/flowstallion.db"), "path to the SQLite database")
	addr := flag.String("addr", envOr("FLOWSTALLION_ADDR", ":8080"), "HTTP listen address")
	flag.Parse()

	if err := run(*dbPath, *addr); err != nil {
		log.Fatalf("scheduler: %v", err)
	}
}

func run(dbPath, addr string) error {
	if dbPath != "" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			return fmt.Errorf("create db dir %q: %w", filepath.Dir(dbPath), err)
		}
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	dispatcher := api.NewDispatcher()
	executor := &api.AgentExecutor{D: dispatcher}
	sched := scheduler.New(st, executor)
	sched.Cfg.Autonomy = int(policy.ParseLevel(envOr("FLOWSTALLION_AUTONOMY", "2")))
	// P7⑦: webhook notifications on run terminal states and canary
	// rollbacks; send failures are logged and never affect the run.
	sched.Notifier = notify.NewWebhookSender()
	srv := api.New(st, sched, dispatcher)

	// P6①: AuthN/RBAC. Off by default (open, pre-P6 behaviour).
	authOn := strings.EqualFold(strings.TrimSpace(os.Getenv("FLOWSTALLION_AUTH")), "on")
	ttl := 168 * time.Hour
	if v := strings.TrimSpace(os.Getenv("FLOWSTALLION_SESSION_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("FLOWSTALLION_SESSION_TTL: %w", err)
		}
		ttl = d
	}
	agentToken := os.Getenv("FLOWSTALLION_AGENT_TOKEN")
	srv.Auth = auth.New(st, authOn, ttl, agentToken)
	if authOn {
		if err := bootstrapAdmin(st); err != nil {
			return err
		}
		if !srv.Auth.AgentTokenSet() {
			log.Printf("auth: WARNING FLOWSTALLION_AGENT_TOKEN is not set; /api/agent/* is open (no authentication) - treat this deployment as machine-untrusted")
		}
		go purgeSessionsLoop(st)
	}

	// P6②: secret vault. Enabled when FLOWSTALLION_SECRET_KEY is set (64 hex
	// chars, or base64 of a 32-byte key). When disabled, pipelines that
	// declare secrets fail the trigger with ErrSecrets.
	if keyStr := strings.TrimSpace(os.Getenv("FLOWSTALLION_SECRET_KEY")); keyStr != "" {
		key, kerr := secret.KeyFromString(keyStr)
		if kerr != nil {
			return fmt.Errorf("FLOWSTALLION_SECRET_KEY: %w", kerr)
		}
		vault, verr := secret.New(key)
		if verr != nil {
			return fmt.Errorf("FLOWSTALLION_SECRET_KEY: %w", verr)
		}
		sched.SecretVault = vault
		srv.Vault = vault
		log.Printf("secrets: enabled (AES-256-GCM)")
	} else {
		log.Printf("secrets: disabled (FLOWSTALLION_SECRET_KEY not set)")
	}

	// P3: background driver for K8s canary releases (no-op when none active).
	// P7⑤: the kubectl binary is configurable (FLOWSTALLION_KUBECTL_BIN) and
	// shared with the in-process k8s_canary step executor.
	kubectl := cd.RealKubectl{Binary: strings.TrimSpace(os.Getenv("FLOWSTALLION_KUBECTL_BIN"))}
	canaryCtl := cd.NewController(st, kubectl)
	sched.CanaryExec = scheduler.NewCanaryExecutor(st, kubectl)
	// P7⑧: operator-triggered rollback (POST /api/canaries/{id}/rollback).
	srv.CanaryCtl = canaryCtl
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						// m-6: a panic in one tick must not kill the
						// scheduler process (and the HTTP API with it).
						log.Printf("cd: tick panic (recovered): %v", rec)
					}
				}()
				canaryCtl.TickAll()
			}()
		}
	}()

	// P7③: background scan for cron (schedule) triggers, every 30 seconds.
	// A tick that misses a due slot fires at most one catch-up run; the
	// last-fire watermark persists across restarts (schedule_state table).
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("cron: tick panic (recovered): %v", rec)
					}
				}()
				if err := sched.CronTick(); err != nil {
					log.Printf("cron: tick failed: %v", err)
				}
			}()
		}
	}()

	// P7⑧: log/canary-event retention. "<n>d" purges rows older than n
	// days, "runs=<n>" keeps the newest n runs' logs. Unset = disabled;
	// an invalid value is logged and ignored so a typo cannot take the
	// scheduler down. One catch-up tick at startup, then every 5 minutes.
	if raw := strings.TrimSpace(os.Getenv("FLOWSTALLION_LOG_RETENTION")); raw != "" {
		pol, rerr := scheduler.ParseRetention(raw)
		if rerr != nil {
			log.Printf("retention: invalid FLOWSTALLION_LOG_RETENTION %q: %v (disabled)", raw, rerr)
		} else {
			sched.Retention = pol
			log.Printf("retention: enabled (policy %q, tick every 5m)", raw)
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("retention: tick panic (recovered): %v", rec)
					}
				}()
				tick := func() {
					if _, err := sched.RetentionTick(); err != nil {
						log.Printf("retention: tick failed: %v", err)
					}
				}
				tick() // catch up on rows written before this process started
				ticker := time.NewTicker(5 * time.Minute)
				defer ticker.Stop()
				for range ticker.C {
					tick()
				}
			}()
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	// P7⑦: base URL for the "url" field of webhook payloads (the console
	// page for a run). Honours FLOWSTALLION_WEB_BASE_URL, else derives from
	// the bound address (a wildcard host becomes "localhost").
	webBase := consoleBaseURL(ln.Addr())
	sched.Cfg.WebBaseURL = webBase
	if ce, ok := sched.CanaryExec.(*scheduler.CanaryExecutor); ok {
		ce.WebBaseURL = webBase
	}
	log.Printf("FlowStallion scheduler listening on %s (db=%s, autonomy=L%d, webBase=%s)", ln.Addr(), dbPath, sched.Cfg.Autonomy, webBase)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           web.New(srv.Handler(), srv.Auth), // console pages + /api/* fall-through
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(ln)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Printf("scheduler stopped")
	return nil
}

// bootstrapAdmin creates the initial admin account when the users table is
// empty and FLOWSTALLION_ADMIN_USERNAME/FLOWSTALLION_ADMIN_PASSWORD are set.
// Fails fast if auth is on, the table is empty, and no bootstrap credentials
// were provided.
func bootstrapAdmin(st *store.Store) error {
	users, err := st.ListUsers()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	if len(users) > 0 {
		log.Printf("auth: %d user(s) present, skipping admin bootstrap", len(users))
		return nil
	}
	name := strings.TrimSpace(os.Getenv("FLOWSTALLION_ADMIN_USERNAME"))
	pass := os.Getenv("FLOWSTALLION_ADMIN_PASSWORD")
	if name == "" || pass == "" {
		return fmt.Errorf("auth enabled but users table is empty: set FLOWSTALLION_ADMIN_USERNAME and FLOWSTALLION_ADMIN_PASSWORD to bootstrap the first admin")
	}
	if !bootstrapUserRe.MatchString(name) {
		return fmt.Errorf("FLOWSTALLION_ADMIN_USERNAME %q invalid: must be 3-64 chars of [A-Za-z0-9._-]", name)
	}
	if len(pass) < 8 {
		return fmt.Errorf("FLOWSTALLION_ADMIN_PASSWORD must be at least 8 characters")
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return fmt.Errorf("hash bootstrap password: %w", err)
	}
	if _, err := st.CreateUser(name, hash, string(auth.RoleAdmin)); err != nil {
		return fmt.Errorf("create bootstrap admin %q: %w", name, err)
	}
	log.Printf("auth: bootstrapped admin user %q", name)
	return nil
}

// purgeSessionsLoop drops expired sessions every 10 minutes.
func purgeSessionsLoop(st *store.Store) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if n, err := st.PurgeExpiredSessions(time.Now().UTC().Format(time.RFC3339)); err == nil && n > 0 {
			log.Printf("auth: purged %d expired session(s)", n)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// consoleBaseURL returns the web console base used for the "url" field of
// webhook payloads (P7⑦). FLOWSTALLION_WEB_BASE_URL wins (trailing slash
// trimmed); otherwise the base is derived from the bound listen address,
// substituting "localhost" for a wildcard host so the URL is usable.
func consoleBaseURL(lnAddr net.Addr) string {
	if v := strings.TrimSpace(os.Getenv("FLOWSTALLION_WEB_BASE_URL")); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	host, port, err := net.SplitHostPort(lnAddr.String())
	if err != nil {
		return "http://" + lnAddr.String()
	}
	switch host {
	case "", "::", "0.0.0.0":
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}
