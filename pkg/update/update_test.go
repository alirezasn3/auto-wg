package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"v1.2.3", "v1.2.4", true},
		{"v1.2.3", "v1.3.0", true},
		{"v1.9.0", "v1.10.0", true}, // numeric, not lexical
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.4", "v1.2.3", false},
		{"1.2.3", "v1.2.4", true},
		{"v1.2.3-rc1", "v1.2.3", false}, // pre-release suffix ignored
		{"dev", "v0.1.0", true},
		{"", "v0.1.0", true},
		{"v1.0.0", "nightly", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.cur, c.latest, got, c.want)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	in := sum + "  autowg_linux_amd64\n" + strings.Repeat("cd", 32) + " *autowg_linux_arm64\nnot a line\n"
	got, err := checksumFor(strings.NewReader(in), "autowg_linux_amd64")
	if err != nil || got != sum {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := checksumFor(strings.NewReader(in), "autowg_linux_arm64"); err != nil || got != strings.Repeat("cd", 32) {
		t.Fatalf("binary-mode marker not handled: %q, %v", got, err)
	}
	if _, err := checksumFor(strings.NewReader(in), "autowg_darwin_arm64"); err == nil {
		t.Fatal("a missing entry must be an error")
	}
	if _, err := checksumFor(strings.NewReader("short  autowg_linux_amd64\n"), "autowg_linux_amd64"); err == nil {
		t.Fatal("a malformed digest must not be accepted")
	}
}

type fakeRelease struct {
	tag      string
	binary   string // content of the platform binary
	sumsFor  string // content the checksums.txt claims; empty = real hash
	noSums   bool
	noBinary bool
}

func serve(t *testing.T, fr fakeRelease) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		rel := Release{Tag: fr.tag, URL: "https://example.test/release", Notes: "notes"}
		if !fr.noBinary {
			rel.Assets = append(rel.Assets, Asset{Name: AssetName(), URL: srv.URL + "/dl/bin"})
		}
		if !fr.noSums {
			rel.Assets = append(rel.Assets, Asset{Name: "checksums.txt", URL: srv.URL + "/dl/sums"})
		}
		_ = json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/dl/bin", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(fr.binary)) })
	mux.HandleFunc("/dl/sums", func(w http.ResponseWriter, r *http.Request) {
		content := fr.sumsFor
		if content == "" {
			content = fr.binary
		}
		h := sha256.Sum256([]byte(content))
		_, _ = fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(h[:]), AssetName())
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	return srv
}

func script(version string) string { return "#!/bin/sh\necho autowg " + version + "\n" }

func installTarget(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "autowg")
	if err := os.WriteFile(p, []byte(script("0.0.1")), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckAndInstall(t *testing.T) {
	serve(t, fakeRelease{tag: "v1.2.3", binary: script("1.2.3")})
	info, rel, err := Check(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || info.Latest != "v1.2.3" || info.Dev || info.Asset != AssetName() {
		t.Fatalf("unexpected info %+v", info)
	}
	exe := installTarget(t)
	if err := Install(context.Background(), rel, exe); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != script("1.2.3") {
		t.Fatalf("binary not replaced: %q", got)
	}
	if st, _ := os.Stat(exe); st.Mode()&0o111 == 0 {
		t.Fatal("installed binary is not executable")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".autowg-update-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

func TestInstallRefusesBadReleases(t *testing.T) {
	cases := []struct {
		name string
		fr   fakeRelease
		want string
	}{
		{"checksum mismatch", fakeRelease{tag: "v1.2.3", binary: script("1.2.3"), sumsFor: script("evil")}, "checksum mismatch"},
		{"no checksums", fakeRelease{tag: "v1.2.3", binary: script("1.2.3"), noSums: true}, "checksums.txt"},
		{"no binary for this platform", fakeRelease{tag: "v1.2.3", binary: script("1.2.3"), noBinary: true}, "no autowg_"},
		{"binary reports another version", fakeRelease{tag: "v1.2.3", binary: script("9.9.9")}, "expected v1.2.3"},
		{"binary does not run", fakeRelease{tag: "v1.2.3", binary: "not an executable"}, "does not run"},
	}
	for _, c := range cases {
		serve(t, c.fr)
		rel, err := Latest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		exe := installTarget(t)
		err = Install(context.Background(), rel, exe)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.want)
		}
		got, _ := os.ReadFile(exe)
		if string(got) != script("0.0.1") {
			t.Errorf("%s: the existing binary was modified", c.name)
		}
	}
}

func TestGetOnlyAllowsHTTPS(t *testing.T) {
	if _, err := get(context.Background(), "http://example.com/x", ""); err == nil || !strings.Contains(err.Error(), "only https") {
		t.Fatalf("plain http to a remote host must be refused, got %v", err)
	}
}

func TestDevBuildCountsAsOlder(t *testing.T) {
	serve(t, fakeRelease{tag: "v0.1.0", binary: script("0.1.0")})
	info, _, err := Check(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Dev || !info.Available {
		t.Fatalf("unexpected info %+v", info)
	}
}

func TestNoReleaseYet(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	if _, err := Latest(context.Background()); err != ErrNoRelease {
		t.Fatalf("got %v, want ErrNoRelease", err)
	}
}
