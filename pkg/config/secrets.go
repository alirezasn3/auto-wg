package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaskSecrets returns a copy of cfg that is safe to hand to the web UI: the web password and every
// tunnel's tls.secret are replaced by MaskedSecret. The input is not modified.
func MaskSecrets(cfg Config) Config {
	if cfg.Web.Password != "" {
		cfg.Web.Password = MaskedSecret
	}
	tunnels := append([]TunnelConfig(nil), cfg.Tunnels...)
	for i := range tunnels {
		if tunnels[i].TLS.Secret != "" {
			tunnels[i].TLS.Secret = MaskedSecret
		}
	}
	cfg.Tunnels = tunnels
	return cfg
}

// RestoreMaskedSecretsConfig puts the stored secrets back into a configuration that came back from the web
// UI with masked values.
func RestoreMaskedSecretsConfig(newCfg, old *Config) error {
	if newCfg.Web.Password == MaskedSecret {
		newCfg.Web.Password = old.Web.Password
	}
	for i := range newCfg.Tunnels {
		t := &newCfg.Tunnels[i]
		if t.TLS.Secret != MaskedSecret {
			continue
		}
		stored, ok := storedTLSSecret(old, t.Interface)
		if !ok {
			return fmt.Errorf("tunnel %q: tls.secret is masked but no secret is stored for this interface; enter it again", t.Interface)
		}
		t.TLS.Secret = stored
	}
	return nil
}

func storedTLSSecret(cfg *Config, iface string) (string, bool) {
	for _, t := range cfg.Tunnels {
		if t.Interface == iface && t.TLS.Secret != "" {
			return t.TLS.Secret, true
		}
	}
	return "", false
}

// secretRef is one secret scalar found in a YAML document.
type secretRef struct {
	iface string // tunnel interface for a tls.secret, empty for the web password
	web   bool
	node  *yaml.Node
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func findSecrets(yamlStr string) ([]secretRef, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(yamlStr), &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	root := doc.Content[0]
	var refs []secretRef
	if pw := mapValue(mapValue(root, "web"), "password"); pw != nil && pw.Kind == yaml.ScalarNode {
		refs = append(refs, secretRef{web: true, node: pw})
	}
	if tunnels := mapValue(root, "tunnels"); tunnels != nil && tunnels.Kind == yaml.SequenceNode {
		for _, t := range tunnels.Content {
			sec := mapValue(mapValue(t, "tls"), "secret")
			if sec == nil || sec.Kind != yaml.ScalarNode {
				continue
			}
			iface := ""
			if n := mapValue(t, "interface"); n != nil {
				iface = n.Value
			}
			refs = append(refs, secretRef{iface: iface, node: sec})
		}
	}
	return refs, nil
}

// rawTokenLen is the length of the scalar's token in its source line, quotes included.
func rawTokenLen(line string, n *yaml.Node) (int, bool) {
	col := n.Column - 1
	if col < 0 || col >= len(line) {
		return 0, false
	}
	rest := line[col:]
	switch n.Style {
	case yaml.DoubleQuotedStyle:
		for i := 1; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
			} else if rest[i] == '"' {
				return i + 1, true
			}
		}
	case yaml.SingleQuotedStyle:
		for i := 1; i < len(rest); i++ {
			if rest[i] == '\'' {
				if i+1 < len(rest) && rest[i+1] == '\'' {
					i++
					continue
				}
				return i + 1, true
			}
		}
	case 0:
		if strings.HasPrefix(rest, n.Value) {
			return len(n.Value), true
		}
	}
	return 0, false
}

type edit struct {
	line, col, length int
	text              string
}

// applyEdits replaces tokens in place so the rest of the document (comments, spacing, ordering) is
// preserved byte for byte.
func applyEdits(yamlStr string, edits []edit) (string, error) {
	lines := strings.Split(yamlStr, "\n")
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].line != edits[j].line {
			return edits[i].line > edits[j].line
		}
		return edits[i].col > edits[j].col
	})
	for _, e := range edits {
		if e.line < 1 || e.line > len(lines) || e.col < 0 || e.col+e.length > len(lines[e.line-1]) {
			return "", fmt.Errorf("cannot locate a secret in the YAML text (line %d)", e.line)
		}
		l := lines[e.line-1]
		lines[e.line-1] = l[:e.col] + e.text + l[e.col+e.length:]
	}
	return strings.Join(lines, "\n"), nil
}

func quoteYAML(s string) string { return strconv.Quote(s) }

// rewriteSecrets replaces every secret scalar for which pick returns a replacement.
func rewriteSecrets(yamlStr string, pick func(ref secretRef) (string, bool, error)) (string, error) {
	refs, err := findSecrets(yamlStr)
	if err != nil {
		return "", err
	}
	lines := strings.Split(yamlStr, "\n")
	var edits []edit
	for _, ref := range refs {
		repl, ok, err := pick(ref)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		if ref.node.Line < 1 || ref.node.Line > len(lines) {
			return "", fmt.Errorf("cannot locate a secret in the YAML text (line %d)", ref.node.Line)
		}
		length, found := rawTokenLen(lines[ref.node.Line-1], ref.node)
		if !found {
			return "", fmt.Errorf("unsupported YAML formatting for the secret on line %d (use a quoted string)", ref.node.Line)
		}
		edits = append(edits, edit{line: ref.node.Line, col: ref.node.Column - 1, length: length, text: quoteYAML(repl)})
	}
	if len(edits) == 0 {
		return yamlStr, nil
	}
	return applyEdits(yamlStr, edits)
}

// MaskYAML hides the web password and every tls.secret in YAML text shown in the web UI. Text that cannot
// be parsed is returned unchanged.
func MaskYAML(yamlStr string) string {
	out, err := rewriteSecrets(yamlStr, func(ref secretRef) (string, bool, error) {
		return MaskedSecret, ref.node.Value != "" && ref.node.Value != MaskedSecret, nil
	})
	if err != nil {
		return yamlStr
	}
	return out
}

// RestoreMaskedSecrets replaces masked secrets in YAML text coming back from the web UI by the stored
// ones, matching tunnels by interface name. Everything else in the text is left untouched.
func RestoreMaskedSecrets(yamlStr string, old *Config) (string, error) {
	return rewriteSecrets(yamlStr, func(ref secretRef) (string, bool, error) {
		if ref.node.Value != MaskedSecret {
			return "", false, nil
		}
		if ref.web {
			return old.Web.Password, true, nil
		}
		stored, ok := storedTLSSecret(old, ref.iface)
		if !ok {
			return "", false, fmt.Errorf("tunnel %q: tls.secret is masked but no secret is stored for this interface; enter it again", ref.iface)
		}
		return stored, true, nil
	})
}
