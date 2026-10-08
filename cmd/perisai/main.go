// Command perisai menjalankan Perisai WAF (Go): reverse proxy + dashboard admin.
//
// Contoh:
// perisai --config config.yaml
// perisai --config config.yaml --ui-dir /opt/perisai/ui/dist
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/willy911/perisai-waf/internal/agent"
	"github.com/willy911/perisai-waf/internal/cache"
	"github.com/willy911/perisai-waf/internal/config"
	"github.com/willy911/perisai-waf/internal/dashboard"
	"github.com/willy911/perisai-waf/internal/geo"
	"github.com/willy911/perisai-waf/internal/iplists"
	"github.com/willy911/perisai-waf/internal/proxy"
	"github.com/willy911/perisai-waf/internal/ratelimit"
	"github.com/willy911/perisai-waf/internal/reputation"
	"github.com/willy911/perisai-waf/internal/rules"
	"github.com/willy911/perisai-waf/internal/storage"
)

// proxyTLSReloader mengadaptasi *proxy.Server ke dashboard.TLSReloader.
type proxyTLSReloader struct{ s *proxy.Server }

func (p proxyTLSReloader) ReloadTLS() error {
	p.s.ReloadCertificates()
	return nil
}

func strVal(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func main() {
	configPath := flag.String("config", "config.yaml", "path file konfigurasi YAML")
	uiDir := flag.String("ui-dir", "ui/dist", "direktori hasil build dashboard Svelte")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("gagal membaca config: %v", err)
	}
	cfg.ConfigPath = *configPath

	// Override via environment variable (instalasi Docker).
	if err := config.ApplyEnv(cfg); err != nil {
		log.Fatalf("gagal menerapkan env: %v", err)
	}

	store, err := storage.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("gagal membuka database: %v", err)
	}

	// Custom rules dari auto-learning sebelumnya.
	var custom []rules.Rule
	if crs, err := store.ListCustomRules(); err == nil {
		for _, m := range crs {
			r, err := rules.NewRule(
				strVal(m, "id"), strVal(m, "name"),
				strVal(m, "category"), strVal(m, "severity"),
				strVal(m, "pattern"),
			)
			if err != nil {
				log.Printf("peringatan: custom rule %q dilewati: %v", strVal(m, "id"), err)
				continue
			}
			custom = append(custom, r)
		}
	}
	eng := rules.NewEngine(cfg, custom)
	orch := agent.NewOrchestrator(cfg, store)

	// Dependensi bersama proxy & dashboard.
	limiter := ratelimit.New(cfg.RateLimit.RPS, cfg.RateLimit.Burst)
	rep := reputation.New(cfg.Reputation, store)
	lists := iplists.New(store)
	pcache := cache.New()
	geoInst := geo.New(cfg.Geo, cfg.DataDir, store)

	proxySrv := proxy.NewServer(cfg, eng, orch, store, limiter, rep, lists, pcache, geoInst)

	// SPA dashboard dari direktori (seperti Python); nil bila tak ada.
	var spaFS fs.FS
	if st, err := os.Stat(*uiDir); err == nil && st.IsDir() {
		abs, _ := filepath.Abs(*uiDir)
		spaFS = os.DirFS(abs)
	} else {
		log.Printf("peringatan: %s tidak ada — dashboard tanpa UI", *uiDir)
	}

	dash := dashboard.New(cfg, store, orch, eng, spaFS,
		lists, pcache, geoInst,
		proxyTLSReloader{proxySrv},
		proxySrv, // dashboard.DisabledSync: toggle rule berlaku langsung
	)

	// Dashboard di goroutine; proxy di goroutine utama agar error fatal terlihat.
	if cfg.Dashboard.Enabled {
		addr := net.JoinHostPort(cfg.Dashboard.Host, strconv.Itoa(cfg.Dashboard.Port))
		srv := &http.Server{
			Addr:              addr,
			Handler:           dash.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			fmt.Printf("[perisai] dashboard http://%s\n", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("dashboard berhenti: %v", err)
			}
		}()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	}

	fmt.Printf("[perisai] proxy :%d -> %s:%d\n", cfg.Server.Port, cfg.Server.UpstreamHost, cfg.Server.UpstreamPort)

	proxyErr := make(chan error, 1)
	go func() { proxyErr <- proxySrv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		fmt.Printf("\n[perisai] menerima %s, berhenti...\n", sig)
	case err := <-proxyErr:
		if err != nil {
			log.Fatalf("proxy berhenti: %v", err)
		}
	}
}
