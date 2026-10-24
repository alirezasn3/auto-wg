// Package update installs new Auto-WG versions from GitHub releases.
//
// A release carries one binary per platform, named autowg_<os>_<arch>, and a checksums.txt in `sha256sum`
// format. The binary is only installed when its SHA-256 matches the checksums.txt of the same release.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are fetched from.
const Repo = "alirezasn3/auto-wg"

// apiBase is the GitHub API root; tests point it at a local server.
var apiBase = "https://api.github.com"

// Release is the part of a GitHub release the updater uses.
type Release struct {
	Tag    string  `json:"tag_name"`
	Name   string  `json:"name"`
	URL    string  `json:"html_url"`
	Notes  string  `json:"body"`
	Assets []Asset `json:"assets"`
}

// Asset is one file attached to a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Info is what the dashboard and the CLI show about the update state.
type Info struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Dev       bool   `json:"dev"` // the running binary is not a release build
	URL       string `json:"url,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Asset     string `json:"asset"`
}

// AssetName is the release file for this platform.
func AssetName() string { return assetFor(runtime.GOOS, runtime.GOARCH) }

func assetFor(goos, goarch string) string { return "autowg_" + goos + "_" + goarch }

var httpClient = &http.Client{Timeout: 5 * time.Minute}

func get(ctx context.Context, rawURL string, accept string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("refusing to fetch %q: only https is allowed", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "auto-wg-updater")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	// Only the API host gets the token, never the redirected download host.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && strings.HasPrefix(rawURL, apiBase) {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &httpError{URL: rawURL, Status: resp.StatusCode}
	}
	return resp, nil
}

type httpError struct {
	URL    string
	Status int
}

func (e *httpError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.URL, e.Status) }

// ErrNoRelease means the repository has no published release yet.
var ErrNoRelease = errors.New("no release has been published yet")

func isLoopback(host string) bool { return host == "127.0.0.1" || host == "localhost" || host == "::1" }

// Latest fetches the newest published release (drafts and pre-releases are not returned by GitHub here).
func Latest(ctx context.Context) (*Release, error) {
	resp, err := get(ctx, apiBase+"/repos/"+Repo+"/releases/latest", "application/vnd.github+json")
	if err != nil {
		var he *httpError
		if errors.As(err, &he) && he.Status == http.StatusNotFound {
			return nil, ErrNoRelease
		}
		return nil, fmt.Errorf("look up the latest release: %w", err)
	}
	defer resp.Body.Close()
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("read the latest release: %w", err)
	}
	if rel.Tag == "" {
		return nil, errors.New("the latest release has no tag")
	}
	return &rel, nil
}

// parseVersion reads "v1.2.3" or "1.2.3-rc1" into numbers; ok is false for anything else (such as "dev").
func parseVersion(v string) (parts [3]int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	fields := strings.Split(v, ".")
	if len(fields) == 0 || len(fields) > 3 {
		return parts, false
	}
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}

// Newer reports whether latest is a higher version than current. A current version that is not a release
// number (a development build) is treated as older than any release.
func Newer(current, latest string) bool {
	l, ok := parseVersion(latest)
	if !ok {
		return false
	}
	c, ok := parseVersion(current)
	if !ok {
		return true
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// Check compares the running version with the latest release.
func Check(ctx context.Context, current string) (*Info, *Release, error) {
	rel, err := Latest(ctx)
	if err != nil {
		return nil, nil, err
	}
	_, isRelease := parseVersion(current)
	return &Info{
		Current: current, Latest: rel.Tag, Available: Newer(current, rel.Tag), Dev: !isRelease,
		URL: rel.URL, Notes: rel.Notes, Asset: AssetName(),
	}, rel, nil
}

func (r *Release) asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// checksumFor finds name's SHA-256 in a sha256sum-format file.
func checksumFor(sums io.Reader, name string) (string, error) {
	sc := bufio.NewScanner(sums)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == sha256.Size*2 {
			return strings.ToLower(f[0]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

// maxBinary bounds the download.
const maxBinary = 200 << 20

// Install downloads rel's binary for this platform, verifies it and replaces the file at exePath.
// The previous binary keeps working until the new one is in place; the running process is not touched.
func Install(ctx context.Context, rel *Release, exePath string) error {
	name := AssetName()
	bin, ok := rel.asset(name)
	if !ok {
		return fmt.Errorf("release %s has no %s for this platform", rel.Tag, name)
	}
	sumsAsset, ok := rel.asset("checksums.txt")
	if !ok {
		return fmt.Errorf("release %s has no checksums.txt; refusing to install an unverified binary", rel.Tag)
	}

	resp, err := get(ctx, sumsAsset.URL, "")
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	want, err := checksumFor(io.LimitReader(resp.Body, 1<<20), name)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	st, err := os.Stat(exePath)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(exePath), ".autowg-update-*")
	if err != nil {
		return fmt.Errorf("create a temporary file next to %s: %w", exePath, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	resp, err = get(ctx, bin.URL, "application/octet-stream")
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("download %s: %w", name, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinary+1))
	_ = resp.Body.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	if n > maxBinary {
		return fmt.Errorf("%s is larger than %d MB", name, maxBinary>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: release says %s, downloaded file is %s", name, want, got)
	}

	if err := os.Chmod(tmpPath, st.Mode().Perm()|0o111); err != nil {
		return err
	}
	// The new binary must at least start on this machine and say which version it is.
	out, err := exec.CommandContext(ctx, tmpPath, "-version").Output()
	if err != nil {
		return fmt.Errorf("the downloaded binary does not run here: %w", err)
	}
	if !strings.Contains(string(out), strings.TrimPrefix(rel.Tag, "v")) {
		return fmt.Errorf("the downloaded binary reports %q, expected %s", strings.TrimSpace(string(out)), rel.Tag)
	}

	// Renaming over the running executable is safe on Unix: the running process keeps its old inode.
	if err := os.Rename(tmpPath, exePath); err != nil {
		return fmt.Errorf("replace %s: %w", exePath, err)
	}
	return nil
}
