package transport

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auto-wg/pkg/config"
)

func TestKnownHostsLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ssh-ed25519 AAAAC3Nza root@host", "alias ssh-ed25519 AAAAC3Nza\n"},
		{"  ecdsa-sha2-nistp256   AAAAE2 ", "alias ecdsa-sha2-nistp256 AAAAE2\n"},
		{"example.com,1.2.3.4 ssh-rsa AAAAB3", "alias ssh-rsa AAAAB3\n"},
	}
	for _, c := range cases {
		got, err := knownHostsLine("alias", c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := knownHostsLine("alias", "garbage"); err == nil {
		t.Error("a host key without a key type must be rejected")
	}
}

// sshd is a real OpenSSH server run as the current user on a loopback port.
type sshd struct {
	port     int
	identity string
	hostKey  string
	user     string
}

func startSSHD(t *testing.T, permitopen string) *sshd {
	t.Helper()
	sshdBin := "/usr/sbin/sshd"
	if p, err := exec.LookPath("sshd"); err == nil {
		sshdBin = p
	}
	if _, err := os.Stat(sshdBin); err != nil {
		t.Skip("no sshd on this machine")
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh client on this machine")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}

	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(keygen, args...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}
	hostKeyFile, idFile := filepath.Join(dir, "host_key"), filepath.Join(dir, "id")
	run("-q", "-t", "ed25519", "-N", "", "-f", hostKeyFile)
	run("-q", "-t", "ed25519", "-N", "", "-f", idFile)
	pub, _ := os.ReadFile(idFile + ".pub")
	hostPub, _ := os.ReadFile(hostKeyFile + ".pub")
	auth := filepath.Join(dir, "authorized_keys")
	line := strings.TrimSpace(string(pub))
	if permitopen != "" {
		line = fmt.Sprintf(`restrict,port-forwarding,permitopen="%s" %s`, permitopen, line)
	}
	if err := os.WriteFile(auth, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
AuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
AllowUsers %s
`, port, hostKeyFile, filepath.Join(dir, "pid"), auth, u.Username)
	cfgFile := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sshdBin, "-D", "-e", "-f", cfgFile)
	var logs lockedBuf
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			return &sshd{port: port, identity: idFile, hostKey: strings.TrimSpace(string(hostPub)), user: u.Username}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Skipf("sshd did not start: %s", logs.String())
	return nil
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// sshPair starts A (dials through ssh into sshd) and B (accept only, behind that sshd).
func sshPair(t *testing.T, srv *sshd, hostKey, secretA, secretB string) (a, b *Link, ra, rb *recorder) {
	t.Helper()
	aRange, _ := portBlock(5, 1)
	bLink := freePort(t)
	optsA := Options{
		Kind: config.TransportSSH, PortRange: aRange, RemotePortRange: fmt.Sprintf("%d-%d", srv.port, srv.port),
		Link: testCfg("", "", secretA).Link,
		SSH: config.SSHConfig{
			User: srv.user, IdentityFile: srv.identity, HostKey: hostKey, SSHPath: "ssh",
			SshdPort: 22, LinkPort: freePort(t),
		},
	}
	optsB := Options{
		Kind: config.TransportSSH, PortRange: "9-9", RemotePortRange: "9-9",
		Link: testCfg("", "", secretB).Link,
		SSH:  config.SSHConfig{SshdPort: srv.port, LinkPort: bLink},
	}
	ra, rb = &recorder{}, &recorder{}
	a = newLink(optsA, "a", testLog(), ra.add, nil)
	b = newLink(optsB, "b", testLog(), rb.add, nil)
	a.car.(*sshCarrier).remoteLinkPort = bLink
	a.SetTargets([]string{"127.0.0.1"})
	a.SetPrimary(true)
	b.SetPrimary(false)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		a.Stop()
		b.Stop()
	})
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSSHLinkOverRealOpenSSH(t *testing.T) {
	srv := startSSHD(t, "")
	a, b, ra, rb := sshPair(t, srv, srv.hostKey, "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 20*time.Second, "ssh link up", func() bool { return a.Connected() && b.Connected() })
	if !a.active.Load().dialed || b.active.Load().dialed {
		t.Fatal("expected A to be the dialer and B the acceptor")
	}
	big := string(make([]byte, 1300))
	for i := 0; i < 20; i++ {
		a.Send([]byte("from-a"))
		b.Send([]byte(big))
	}
	waitFor(t, 5*time.Second, "packets delivered both ways", func() bool { return rb.has("from-a") && ra.has(big) })

	// A dropped connection is rebuilt by the dial loop.
	if !a.ResetConn() {
		t.Fatal("reset found no connection")
	}
	waitFor(t, 20*time.Second, "ssh link rebuilt", func() bool { return a.Connected() && b.Connected() })
}

func TestSSHLinkWorksWithRestrictedKey(t *testing.T) {
	// The key may do nothing but forward to the link port, as the README recommends.
	srv := startSSHD(t, "127.0.0.1:*")
	a, b, ra, rb := sshPair(t, srv, srv.hostKey, "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 20*time.Second, "ssh link up with a restricted key", func() bool { return a.Connected() && b.Connected() })
	a.Send([]byte("from-a"))
	waitFor(t, 5*time.Second, "packet delivered", func() bool { return rb.has("from-a") })
	_ = ra
}

func TestSSHRejectsWrongHostKey(t *testing.T) {
	srv := startSSHD(t, "")
	other := startSSHD(t, "")
	a, b, _, _ := sshPair(t, srv, other.hostKey, "shared-secret-1234", "shared-secret-1234")
	waitFor(t, 20*time.Second, "host key failure reported", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return strings.Contains(a.lastErr, "Host key verification failed")
	})
	if a.Connected() || b.Connected() {
		t.Fatal("a link must not come up against an unexpected host key")
	}
}

func TestSSHWrongSecretNeverVerifies(t *testing.T) {
	srv := startSSHD(t, "")
	a, b, _, _ := sshPair(t, srv, srv.hostKey, "shared-secret-1234", "another-secret-9876")
	waitFor(t, 20*time.Second, "auth failure counted", func() bool { return b.st.authFails.Load() > 0 })
	if a.Connected() || b.Connected() {
		t.Fatal("peers with different secrets must not connect")
	}
}

func TestSSHAcceptOnlyPeerDoesNotDial(t *testing.T) {
	c := &sshCarrier{}
	if _, err := c.dial(nil, "127.0.0.1", 22); err != errNoDial {
		t.Fatalf("got %v, want errNoDial", err)
	}
}
