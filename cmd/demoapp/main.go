// Command demoapp is a tiny HTTP application used to exercise FlowStallion's
// K8s canary controller. It serves:
//
//	/         ok (or a 500, when the injected failure rate strikes)
//	/version  the build version label
//	/metrics  cumulative counters as JSON (always 200 — it is the probe
//	           endpoint the canary controller scrapes)
//
// The version and failure rate are injected at build time:
//
//	go build -ldflags "-X main.version=v2 -X main.failRate=0.8"
//
// The /metrics endpoint never fails on purpose: in a real release the
// observability endpoint stays up even when the app logic is broken, and
// the canary controller relies on its error counters to detect the failure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Build-time knobs (see demo/Dockerfile.demoapp).
var (
	version  = "dev"
	failRate = "0"
)

func main() {
	port := flag.String("port", "8080", "listen port")
	flag.StringVar(&version, "version", version, "version label (build-time override)")
	var frOverride float64
	flag.Float64Var(&frOverride, "fail-rate", -1, "override failure rate 0..1 (-1 keeps the build value)")
	flag.Parse()

	fail, err := strconv.ParseFloat(failRate, 64)
	if err != nil {
		log.Fatalf("demoapp: bad build fail-rate %q: %v", failRate, err)
	}
	if frOverride >= 0 {
		fail = frOverride
	}
	if fail < 0 || fail > 1 {
		log.Fatalf("demoapp: fail rate out of range: %v", fail)
	}

	var (
		requests int64
		errorsN  int64
		scrapes  int64
	)
	start := time.Now()
	var mu sync.Mutex
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	flip := func() bool {
		atomic.AddInt64(&requests, 1)
		if fail > 0 {
			mu.Lock()
			hit := rng.Float64() < fail
			mu.Unlock()
			if hit {
				atomic.AddInt64(&errorsN, 1)
			}
			return !hit
		}
		return true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !flip() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok\n")
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if !flip() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, version+"\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// m-4: probes are counted separately so the controller's error-rate
		// window reflects app traffic only, not the controller's own
		// scraping (which previously inflated requests every 2s).
		atomic.AddInt64(&scrapes, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind":      "Metrics",
			"version":   version,
			"requests":  atomic.LoadInt64(&requests),
			"errors":    atomic.LoadInt64(&errorsN),
			"scrapes":   atomic.LoadInt64(&scrapes),
			"fail_rate": fail,
			"uptime_s":  time.Since(start).Seconds(),
		})
	})

	log.Printf("demoapp %s listening on :%s (fail_rate=%.2f)", version, *port, fail)
	log.Fatal(http.ListenAndServe(":"+*port, mux))
}
