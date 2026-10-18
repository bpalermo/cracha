package netconf

import (
	"encoding/json"
	"testing"
	"time"
)

// The entry the installer writes is what the plugin parses, with the
// conflist's additions, and marshals with its keys in the documented order.
func TestEntryRoundTrips(t *testing.T) {
	entry, err := json.Marshal(NewEntry("/run/cracha/cni.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"type":"cracha-cni","socket":"/run/cracha/cni.sock","timeout":"5s"}`; string(entry) != want {
		t.Fatalf("entry = %s, want %s", entry, want)
	}
	stdin := `{"cniVersion":"0.3.1","name":"kindnet","type":"cracha-cni","socket":"/run/cracha/cni.sock","timeout":"5s","prevResult":{"cniVersion":"0.3.1","ips":[]}}`
	conf, err := Parse([]byte(stdin))
	if err != nil {
		t.Fatal(err)
	}
	if conf.Socket != "/run/cracha/cni.sock" || conf.Name != "kindnet" || conf.CNIVersion != "0.3.1" {
		t.Errorf("conf = %+v", conf)
	}
	if d, err := conf.CallTimeout(); err != nil || d != 5*time.Second {
		t.Errorf("timeout = %v, %v", d, err)
	}
	if string(conf.PrevResult) != `{"cniVersion":"0.3.1","ips":[]}` {
		t.Errorf("prevResult = %s", conf.PrevResult)
	}
}

func TestParseRefusals(t *testing.T) {
	for name, stdin := range map[string]string{
		"not json":      `{`,
		"another type":  `{"cniVersion":"0.3.1","name":"n","type":"kindnet","socket":"/s"}`,
		"no socket":     `{"cniVersion":"0.3.1","name":"n","type":"cracha-cni"}`,
		"bad timeout":   `{"cniVersion":"0.3.1","name":"n","type":"cracha-cni","socket":"/s","timeout":"soon"}`,
		"zero timeout":  `{"cniVersion":"0.3.1","name":"n","type":"cracha-cni","socket":"/s","timeout":"0s"}`,
		"minus timeout": `{"cniVersion":"0.3.1","name":"n","type":"cracha-cni","socket":"/s","timeout":"-1s"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(stdin)); err == nil {
				t.Error("parsed")
			}
		})
	}
}

// Without a timeout the default applies.
func TestDefaultTimeout(t *testing.T) {
	conf, err := Parse([]byte(`{"cniVersion":"0.3.1","name":"n","type":"cracha-cni","socket":"/s"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := conf.CallTimeout(); err != nil || d != DefaultTimeout {
		t.Errorf("timeout = %v, %v", d, err)
	}
}
