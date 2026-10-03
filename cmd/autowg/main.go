package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/monitor"
	"auto-wg/pkg/negotiator"
	"auto-wg/pkg/signaling"
	"auto-wg/pkg/web"
	"auto-wg/pkg/wg"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	flag.Parse()

	log := logger.Default()
	if *debug {
		log.SetMinLevel(logger.LevelDebug)
	}

	log.Info("MAIN", "=======================================================")
	log.Info("MAIN", " Starting Auto-WG: Dynamic WireGuard Port Negotiator   ")
	log.Info("MAIN", "=======================================================")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Error("MAIN", "Failed to load config from %s: %v", *configPath, err)
		os.Exit(1)
	}

	log.Info("MAIN", "Loaded configuration for Peer %q (Remote: %q)", cfg.PeerID, cfg.RemotePeerID)
	log.Info("MAIN", "WireGuard interface: %s (mode: %s, command: %s)",
		cfg.WireGuard.Interface, cfg.WireGuard.Mode, cfg.WireGuard.Command)
	log.Info("MAIN", "Candidate ports pool size: %d", len(cfg.Negotiation.CandidatePorts))

	// Initialize WireGuard Controller
	wgCtrl, err := wg.NewController(cfg.WireGuard.Mode, cfg.WireGuard.Command, log)
	if err != nil {
		log.Error("MAIN", "Failed to initialize WireGuard controller: %v", err)
		os.Exit(1)
	}
	defer wgCtrl.Close()

	// Initialize Tiered Signaling Manager
	signaler := signaling.NewCompositeSignaler(cfg, log)

	// Context for graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wire up Negotiator Engine and Health Monitor
	var engine *negotiator.Engine
	mon := monitor.New(cfg, wgCtrl, log, func(reason string) {
		if engine != nil {
			engine.TriggerFailure(reason)
		}
	})

	engine = negotiator.NewEngine(cfg, wgCtrl, signaler, mon, log)

	// Initialize Embedded Web Panel
	var webServer *web.Server
	if cfg.Web.Enabled {
		webServer = web.NewServer(cfg, mon, engine, signaler, wgCtrl, log)
		if err := webServer.Start(); err != nil {
			log.Warn("MAIN", "Failed to start web server: %v", err)
		}
	}

	// Start WireGuard Health Monitoring loop
	go mon.Start(ctx)

	// Announce readiness on signaling channel
	initialState := &signaling.PeerState{
		PeerID: cfg.PeerID,
		Role:   signaling.RoleIdle,
		Epoch:  time.Now().Unix(),
	}
	if err := signaler.PublishState(ctx, initialState); err != nil {
		log.Warn("MAIN", "Initial signaling state publish: %v", err)
	} else {
		log.Info("MAIN", "Initial peer state published across active signaling channels")
	}

	// Handle graceful shutdown on OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	log.Info("MAIN", "Received shutdown signal (%v). Gracefully stopping Auto-WG...", sig)

	cancel()
	if webServer != nil {
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer sCancel()
		_ = webServer.Stop(shutdownCtx)
	}

	fmt.Println("Auto-WG stopped cleanly.")
}
