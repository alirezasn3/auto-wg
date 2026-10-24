package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"auto-wg/pkg/config"
	"auto-wg/pkg/iptables"
	"auto-wg/pkg/logger"
	"auto-wg/pkg/supervisor"
	"auto-wg/pkg/update"
	"auto-wg/pkg/web"
	"auto-wg/pkg/wg"

	goSystemd "github.com/alirezasn3/go-systemd"
)

// version is set at build time (-ldflags "-X main.version=v1.2.3"); "dev" marks a local build.
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	installFlag := flag.Bool("install", false, "Install Auto-WG as a systemd service and start it")
	uninstallFlag := flag.Bool("uninstall", false, "Stop and uninstall the Auto-WG systemd service")
	versionFlag := flag.Bool("version", false, "Print the version and exit")
	checkUpdateFlag := flag.Bool("check-update", false, "Check GitHub for a newer release and exit")
	updateFlag := flag.Bool("update", false, "Install the latest GitHub release over this binary (and restart the systemd service)")
	noRestartFlag := flag.Bool("no-restart", false, "With -update: do not restart the systemd service afterwards")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("autowg %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	log := logger.Default()
	if *debug {
		log.SetMinLevel(logger.LevelDebug)
	}

	if *checkUpdateFlag || *updateFlag {
		os.Exit(handleUpdate(*updateFlag, !*noRestartFlag, log))
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
			cfg = &config.Config{
				Mode: "server",
				Tunnels: []config.TunnelConfig{
					{
						Interface:       "wg0",
						Name:            "Default-Tunnel",
						PortRange:       "20000-30000",
						RemotePortRange: "20000-30000",
						Iptables:        true,
					},
				},
			}
			config.SetDefaults(cfg)
			if saveErr := config.SaveConfig(*configPath, cfg); saveErr != nil {
				log.Warn("MAIN", "Could not save default config: %v", saveErr)
			}
		} else {
			log.Error("MAIN", "Failed to load config from %s: %v", *configPath, err)
			os.Exit(1)
		}
	}

	log.Info("MAIN", "Auto-WG running in %s mode with %d managed tunnel(s)", strings.ToUpper(cfg.Mode), len(cfg.Tunnels))

	// Initialize WireGuard Controller (Pure Netlink / UAPI)
	wgCtrl, err := wg.NewController(log)
	if err != nil {
		log.Warn("MAIN", "Could not initialize netlink wgctrl (%v). Device queries may be limited outside Linux.", err)
	} else {
		defer wgCtrl.Close()
	}

	// Initialize iptables Manager
	iptMgr := iptables.NewManager(log)

	// Initialize Multi-Tunnel Supervisor
	sup := supervisor.New(*configPath, cfg, wgCtrl, iptMgr, log)

	// Context for graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The running executable, resolved now: after an update replaces the file, /proc/self/exe no longer
	// names it.
	exePath, _ := resolveExe()

	// An update from the dashboard asks for a restart, which re-executes the new binary after cleanup.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	var restartRequested atomic.Bool
	requestRestart := func() {
		restartRequested.Store(true)
		sigChan <- syscall.SIGTERM
	}

	// Initialize Web Server(s) (Admin Panel and/or Public Status Page)
	var webServer *web.Server
	if cfg.Web.Enabled || cfg.StatusPage.Enabled {
		webServer = web.NewServer(sup, log)
		if exePath != "" {
			webServer.SetUpdater(&web.Updater{Version: version, Exe: exePath, Restart: requestRestart})
		}
		if err := webServer.Start(); err != nil {
			log.Warn("MAIN", "Failed to start web server(s): %v", err)
		}
	}

	// Start Supervisor in background (manages hunters, PostUp/PreDown, and routing failover)
	supDone := make(chan struct{})
	go func() {
		defer close(supDone)
		sup.Start(ctx)
	}()

	// Handle graceful shutdown on OS signals
	sig := <-sigChan
	log.Info("MAIN", "Received shutdown signal (%v). Gracefully stopping Auto-WG...", sig)

	cancel()

	if webServer != nil {
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer sCancel()
		_ = webServer.Stop(shutdownCtx)
	}

	// The supervisor tears everything down once its context is cancelled (pre_down commands, history,
	// iptables rules, TLS links). Wait for that: exiting right away would leave the rules behind.
	select {
	case <-supDone:
	case <-time.After(45 * time.Second):
		log.Warn("MAIN", "Shutdown cleanup did not finish within 45s; exiting anyway")
	}

	fmt.Println("Auto-WG stopped cleanly.")

	if restartRequested.Load() && exePath != "" {
		log.Info("MAIN", "Restarting into the updated binary %s", exePath)
		if err := syscall.Exec(exePath, os.Args, os.Environ()); err != nil {
			log.Error("MAIN", "Could not start the updated binary: %v (start Auto-WG again manually)", err)
			os.Exit(1)
		}
	}
}

func resolveExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// handleUpdate implements -check-update and -update. It returns the process exit code.
func handleUpdate(install, restart bool, log *logger.Logger) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	info, rel, err := update.Check(ctx, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
		return 1
	}
	fmt.Printf("Running %s, latest release %s (%s)\n", info.Current, info.Latest, info.URL)
	if !info.Available {
		fmt.Println("Already up to date.")
		return 0
	}
	if !install {
		fmt.Printf("Update available. Run `autowg -update` to install it.\n")
		return 0
	}

	exe, err := resolveExe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot locate this executable: %v\n", err)
		return 1
	}
	fmt.Printf("Downloading %s and verifying its checksum...\n", info.Asset)
	if err := update.Install(ctx, rel, exe); err != nil {
		fmt.Fprintf(os.Stderr, "Update failed (the installed binary was not changed): %v\n", err)
		return 1
	}
	fmt.Printf("Installed %s at %s\n", rel.Tag, exe)

	if !restart {
		fmt.Println("Restart the service to run it: sudo systemctl restart autowg")
		return 0
	}
	st, err := goSystemd.StatusService("autowg")
	if err != nil || !st.Exists || !st.Active {
		fmt.Println("The autowg systemd service is not running here; start the new binary yourself.")
		return 0
	}
	fmt.Println("Restarting the autowg systemd service...")
	if err := goSystemd.StopService("autowg"); err != nil {
		fmt.Fprintf(os.Stderr, "Could not stop the service: %v\nRestart it manually: sudo systemctl restart autowg\n", err)
		return 1
	}
	if err := goSystemd.StartService("autowg"); err != nil {
		fmt.Fprintf(os.Stderr, "Could not start the service: %v\nStart it manually: sudo systemctl start autowg\n", err)
		return 1
	}
	fmt.Println("Done.")
	return 0
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
