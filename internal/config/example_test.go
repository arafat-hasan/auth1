package config

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/knadh/koanf/parsers/yaml"
)

const examplePath = "../../config.example.yaml"

// exampleOverrides are the keys whose value in config.example.yaml is not the default: required
// values with no default, the example lists, and file paths pointing at the placeholders.
var exampleOverrides = map[string]bool{
	"http.issuer":       true,
	"clients":           true,
	"mfa.totp.issuer":   true,
	"service_auth.mode": true,
	"service_auth.client_credentials.clients": true,
	"service_auth.callers":                    true,
	"rate_limits.sms_budget_per_hour":         true,
	"keys.keyring_file":                       true,
	"encryption.keyring_file":                 true,
	"encryption.blind_index_key_file":         true,
	"encryption.mac_key_file":                 true,
	"encryption.device_cookie_key_file":       true,
	"passwords.deny_list_file":                true,
	"passwords.pepper_keyring_file":           true,
	"bootstrap.emails_file":                   true,
	"database.dsn_file":                       true,
	"amqp.url_file":                           true,
}

// TestExampleListsEveryKey checks that config.example.yaml names every key of the schema.
func TestExampleListsEveryKey(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Parser().Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for path := range flatten(Default()) {
		if _, ok := lookup(raw, path); !ok {
			t.Errorf("config.example.yaml does not list %s", path)
		}
	}
}

// TestExampleShowsDefaults checks that every value in config.example.yaml is the default, except
// the keys in exampleOverrides.
func TestExampleShowsDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(examplePath, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, want := flatten(*cfg), flatten(Default())
	var differ []string
	for path, v := range got {
		same := reflect.DeepEqual(v, want[path]) || isEmpty(v) && isEmpty(want[path])
		if !same && !exampleOverrides[path] {
			differ = append(differ, path)
		}
	}
	sort.Strings(differ)
	if len(differ) > 0 {
		t.Errorf("config.example.yaml differs from the defaults at:\n%s", strings.Join(differ, "\n"))
	}
}

// TestExamplePlaceholdersExist checks that the example names only placeholder files that exist.
func TestExamplePlaceholdersExist(t *testing.T) {
	t.Parallel()

	cfg, err := Load(examplePath, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for path, v := range flatten(*cfg) {
		if !exampleOverrides[path] || !strings.HasSuffix(path, "_file") {
			continue
		}
		file := filepath.Join("..", "..", strings.TrimPrefix(toString(v), "./"))
		if !strings.HasPrefix(toString(v), "testdata/example/") {
			t.Errorf("%s = %q, want a placeholder under testdata/example/", path, toString(v))
		} else if err := checkFile(file); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func toString(v any) string {
	if f, ok := v.(SecretFile); ok {
		return f.Path()
	}
	s, _ := v.(string)
	return s
}

func isEmpty(v any) bool {
	rv := reflect.ValueOf(v)
	return (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Map) && rv.Len() == 0
}
