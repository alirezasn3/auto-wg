package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/hunter"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/web"
	"auto-wg/pkg/wg"

	goSystemd "github.com/alirezasn3/go-systemd"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	installFlag := flag.Bool("install", false, "Install Auto-WG as a systemd service and start it")
	uninstallFlag := flag.Bool("uninstall", false, "Stop and uninstall the Auto-WG systemd service")
	flag.Parse()

	log := logger.Default()
	if *debug {
		log.SetMinLevel(logger.LevelDebug)
	}

	if *installFlag {
		handleInstall(*configPath, log)
		return
	}

	if *uninstallFlag {
		handleUninstall(log)
		return
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

	// Initialize Web Server(s) (Admin Panel and/or Public Status Page)
	var webServer *web.Server
	if cfg.Web.Enabled || cfg.StatusPage.Enabled {
		webServer = web.NewServer(h, log)
		if err := webServer.Start(); err != nil {
			log.Warn("MAIN", "Failed to start web server(s): %v", err)
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
	_ = h.SaveHistory()

	if webServer != nil {
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer sCancel()
		_ = webServer.Stop(shutdownCtx)
	}

	// Clean up iptables rule on shutdown
	_ = iptMgr.RemoveRule()

	fmt.Println("Auto-WG stopped cleanly.")
}

func handleInstall(configPath string, log *logger.Logger) {
	exePath, err := os.Executable()
	if err != nil {
		log.Error("INSTALL", "Failed to determine executable path: %v", err)
		os.Exit(1)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		log.Error("INSTALL", "Failed to resolve executable symlinks: %v", err)
		os.Exit(1)
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		log.Error("INSTALL", "Failed to determine absolute config path: %v", err)
		os.Exit(1)
	}

	svc := &goSystemd.Service{
		Name:        "autowg",
		Description: "Auto-WG: Autonomous WireGuard Port Negotiator",
		ExecStart:   fmt.Sprintf("%s -config %s", exePath, absConfigPath),
		Restart:     "always",
		RestartSec:  "5s",
		After:       "network.target",
		Wants:       "network.target",
		WantedBy:    "multi-user.target",
	}

	log.Info("INSTALL", "Creating systemd service 'autowg' pointing to executable %s...", exePath)
	if err := goSystemd.CreateService(svc); err != nil {
		log.Error("INSTALL", "Failed to create systemd service: %v", err)
		os.Exit(1)
	}

	_ = goSystemd.DaemonReload()

	log.Info("INSTALL", "Starting systemd service 'autowg'...")
	if err := goSystemd.StartService("autowg"); err != nil {
		log.Warn("INSTALL", "Service created successfully, but starting failed: %v", err)
		log.Info("INSTALL", "You can start it manually with: sudo systemctl start autowg")
	} else {
		log.Info("INSTALL", "Service 'autowg' installed and started successfully!")
	}
}

func handleUninstall(log *logger.Logger) {
	log.Info("UNINSTALL", "Stopping systemd service 'autowg'...")
	_ = goSystemd.StopService("autowg")

	log.Info("UNINSTALL", "Deleting systemd unit file for 'autowg'...")
	if err := goSystemd.DeleteService("autowg"); err != nil {
		log.Error("UNINSTALL", "Failed to delete systemd service: %v", err)
		os.Exit(1)
	}

	_ = goSystemd.DaemonReload()
	log.Info("UNINSTALL", "Service 'autowg' uninstalled successfully!")
}
