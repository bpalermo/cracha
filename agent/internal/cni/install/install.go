// Package install is `cracha-agent cni-install`, the init container of the
// agent DaemonSet in cni mode (docs/design.md, section 7.2): it puts the
// cracha-cni plugin on the node. It copies the plugin binary from the agent
// image into the node's CNI bin directory and appends the plugin's entry
// (agent/cni/netconf) to the plugins of the node's primary conflist, the
// one the runtime uses: the lexically first configuration of the CNI conf
// directory, which must be a conflist, since a plugin can only be chained
// into a plugin list.
//
// Every write is a temp file in the destination's directory, fsynced,
// renamed over the destination, the directory fsynced after: the runtime
// never sees a half-written plugin or conflist. The install is idempotent:
// a binary already identical and a conflist already carrying the entry are
// left alone (the file keeps its inode), and an entry a competing writer
// stripped is appended again on the next run. The runtime re-reads the
// conflist on its next ADD, so nothing is restarted.
//
// Uninstall removes the entry and the binary, for cleanup by hand; the
// chart does not use it.
package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/bpalermo/cracha/agent/cni/netconf"
)

// Defaults the chart's values mirror (agent.cni.*), and where the agent
// image keeps the plugin.
const (
	DefaultPlugin  = "/opt/cracha/cni/cracha-cni"
	DefaultBinDir  = "/opt/cni/bin"
	DefaultConfDir = "/etc/cni/net.d"
	binMode        = fs.FileMode(0o755)
	confMode       = fs.FileMode(0o644)
)

// Config is the installer's.
type Config struct {
	// Plugin is the plugin binary in the image.
	Plugin string
	// BinDir is the node's CNI bin directory, as mounted.
	BinDir string
	// ConfDir is the node's CNI conf directory, as mounted.
	ConfDir string
	// Socket is the agent's socket the entry names (agent.cni.socket).
	Socket string
	Logger *slog.Logger
}

func (c Config) log() *slog.Logger {
	if c.Logger == nil {
		return slog.Default()
	}
	return c.Logger
}

// Run installs: the binary, then the entry.
func Run(cfg Config) error {
	if cfg.Socket == "" {
		return errors.New("the agent's socket is required")
	}
	dst := filepath.Join(cfg.BinDir, netconf.PluginType)
	if err := copyBinary(cfg.log(), cfg.Plugin, dst); err != nil {
		return err
	}
	return chain(cfg.log(), cfg.ConfDir, netconf.NewEntry(cfg.Socket))
}

// Uninstall removes the entry from the primary conflist and the binary.
func Uninstall(cfg Config) error {
	log := cfg.log()
	if err := unchain(log, cfg.ConfDir); err != nil {
		return err
	}
	dst := filepath.Join(cfg.BinDir, netconf.PluginType)
	if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", dst, err)
	}
	log.Info("plugin removed", "path", dst)
	return nil
}

// copyBinary puts src at dst, 0755, unless dst already is src byte for
// byte.
func copyBinary(log *slog.Logger, src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading the plugin: %w", err)
	}
	if same, err := sameFile(dst, data, binMode); err != nil {
		return err
	} else if same {
		log.Info("plugin already installed and unchanged", "path", dst)
		return nil
	}
	if err := writeAtomic(dst, data, binMode); err != nil {
		return fmt.Errorf("installing the plugin: %w", err)
	}
	log.Info("plugin installed", "path", dst, "bytes", len(data))
	return nil
}

// chain appends entry to the primary conflist's plugins, unless it is
// there already.
func chain(log *slog.Logger, confDir string, entry netconf.Entry) error {
	path, conf, err := primary(confDir)
	if err != nil {
		return err
	}
	plugins, _ := conf["plugins"].([]any)
	plugins = without(plugins, netconf.PluginType)
	conf["plugins"] = append(plugins, entry)
	return rewrite(log, path, conf, "entry chained")
}

// unchain removes the entry from the primary conflist, if it is there.
func unchain(log *slog.Logger, confDir string) error {
	path, conf, err := primary(confDir)
	if err != nil {
		return err
	}
	plugins, _ := conf["plugins"].([]any)
	conf["plugins"] = without(plugins, netconf.PluginType)
	return rewrite(log, path, conf, "entry removed")
}

// rewrite writes conf to path unless the file already holds exactly that.
func rewrite(log *slog.Logger, path string, conf map[string]any, what string) error {
	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return fmt.Errorf("rendering %s: %w", path, err)
	}
	data = append(data, '\n')
	if same, err := sameFile(path, data, confMode); err != nil {
		return err
	} else if same {
		log.Info("conflist unchanged", "path", path)
		return nil
	}
	if err := writeAtomic(path, data, confMode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	log.Info(what, "path", path)
	return nil
}

// without is plugins minus the entries of type typ.
func without(plugins []any, typ string) []any {
	out := make([]any, 0, len(plugins))
	for _, p := range plugins {
		if m, ok := p.(map[string]any); ok && m["type"] == typ {
			continue
		}
		out = append(out, p)
	}
	return out
}

// primary is the configuration the runtime uses, parsed: the lexically
// first .conf, .conflist or .json of confDir, which must be a conflist
// (carry a plugin list).
func primary(confDir string) (string, map[string]any, error) {
	entries, err := os.ReadDir(confDir)
	if err != nil {
		return "", nil, fmt.Errorf("reading the CNI conf directory: %w", err)
	}
	var names []string
	for _, e := range entries {
		if ext := filepath.Ext(e.Name()); !e.IsDir() && (ext == ".conf" || ext == ".conflist" || ext == ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", nil, fmt.Errorf("no CNI configuration in %s: the node's primary plugin is not installed yet", confDir)
	}
	sort.Strings(names)
	path := filepath.Join(confDir, names[0])
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	conf, err := parse(data)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, ok := conf["plugins"].([]any); !ok {
		return "", nil, fmt.Errorf("%s is the node's primary CNI configuration and is not a conflist: cracha-cni can only be chained into a plugin list", path)
	}
	return path, conf, nil
}

// parse decodes a configuration, keeping its numbers as written.
func parse(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var conf map[string]any
	if err := dec.Decode(&conf); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	return conf, nil
}

// sameFile reports whether path is a regular file holding data with mode.
func sameFile(path string, data []byte, mode fs.FileMode) (bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != mode || fi.Size() != int64(len(data)) {
		return false, nil
	}
	have, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	return bytes.Equal(have, data), nil
}

// writeAtomic puts data at path with mode: a temp file beside it, written,
// fsynced, given its mode, renamed over path, and the directory fsynced.
func writeAtomic(path string, data []byte, mode fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, bytes.NewReader(data)); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory, so a rename into it is durable. A filesystem
// that cannot fsync a directory (EINVAL) has nothing to make durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}
