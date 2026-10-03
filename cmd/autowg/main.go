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
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
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

	log.Info("MAIN", "=================================================================")
	log.Info("MAIN", " Starting Auto-WG: Autonomous WireGuard Port Negotiator         ")
	log.Info("MAIN", " Zero-Negotiator Mode with iptables Forwarding & Web Dashboard   ")
	log.Info("MAIN", "=================================================================")

	// Load configuration (or generate default if not found)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("MAIN", "Config file %s not found. Creating default configuration...", *configPath)
			cfg = &config.Config{}
			config.SetDefaults(cfg)
			if saveErr := config.SaveConfig(*configPath, cfg); saveErr != nil {
				log.Warn("MAIN", "Could not save default config: %v", saveErr)
			}
		} else {
			log.Error("MAIN", "Failed to load config from %s: %v", *configPath, err)
			os.Exit(1)
		}
	}

	log.Info("MAIN", "WireGuard interface: %s (mode: %s, command: %s)",
		cfg.WireGuard.Interface, cfg.WireGuard.Mode, cfg.WireGuard.Command)
	log.Info("MAIN", "Local port range: %s | Remote port range: %s",
		cfg.Iptables.PortRange, cfg.Hunter.RemotePortRange)

	// Initialize WireGuard Controller
	wgCtrl, err := wg.NewController(cfg.WireGuard.Mode, cfg.WireGuard.Command, log)
	if err != nil {
		log.Error("MAIN", "Failed to initialize WireGuard controller: %v", err)
		os.Exit(1)
	}
	defer wgCtrl.Close()

	// Initialize iptables Manager
	iptMgr := iptables.NewManager(log)

	// Initialize Autonomous Hunter Engine
	h := hunter.New(*configPath, cfg, wgCtrl, iptMgr, log)

	// Context for graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Embedded Web Panel
	var webServer *web.Server
	if cfg.Web.Enabled {
		webServer = web.NewServer(h, log)
		if err := webServer.Start(); err != nil {
			log.Warn("MAIN", "Failed to start web server: %v", err)
		}
	}

	// Start Autonomous Hunter in background
	go h.Start(ctx)

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

	// Clean up iptables rule on shutdown if desired
	_ = iptMgr.RemoveRule()

	fmt.Println("Auto-WG stopped cleanly.")
}
