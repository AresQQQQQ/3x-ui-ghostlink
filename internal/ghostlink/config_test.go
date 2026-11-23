package ghostlink

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const testSecret = "ghostlink-client-secret-32-bytes-minimum"

func testIdentityTLS(t *testing.T) *IdentityTLSConfig {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value []byte) string {
		return base64.RawURLEncoding.EncodeToString(value)
	}
	return &IdentityTLSConfig{
		ServerName: "www.speedtest.net",
		ClientID:   "node-client",
		Secret:     "ghostlink-node-identity-secret-32",
		PrivateKey: encode(privateKey.Bytes()),
		PublicKey:  encode(privateKey.PublicKey().Bytes()),
		ShortID:    "0011223344556677",
	}
}

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ghostlink.example"},
		DNSNames:     []string{"ghostlink.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func validSettings(t *testing.T) Settings {
	t.Helper()
	certPath, keyPath := testCertificate(t)
	return Settings{
		Version:         SchemaVersion,
		CertificateFile: certPath,
		PrivateKeyFile:  keyPath,
		ServerName:      "ghostlink.example",
		WebBackendURL:   "http://127.0.0.1:8080",
		Clients: []model.Client{{
			Email: "alice@example.test", ID: "alice-device", Secret: testSecret, Enable: true,
		}},
	}
}

func marshalSettings(t *testing.T, settings Settings) string {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestBuildDesiredStateMapsCoreConfigAndRedactsSecrets(t *testing.T) {
	settings := validSettings(t)
	inbound := &model.Inbound{
		Id:       7,
		Protocol: model.GhostLink,
		Enable:   true,
		Listen:   "0.0.0.0",
		Port:     8443,
		Settings: marshalSettings(t, settings),
	}
	state, err := BuildDesiredState(inbound, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("BuildDesiredState: %v", err)
	}
	if !state.ShouldRun || state.Reason != "ready" {
		t.Fatalf("desired lifecycle = should_run:%v reason:%q", state.ShouldRun, state.Reason)
	}
	if state.Config.Transport != TransportDualMASQUE {
		t.Fatalf("transport = %q", state.Config.Transport)
	}
	if state.UserRevision == "" {
		t.Fatal("desired state has no runtime user revision")
	}
	if state.Config.LocalControl == nil ||
		state.Config.LocalControl.SocketPath != DefaultControlSocketPath {
		t.Fatalf("local control config = %#v", state.Config.LocalControl)
	}
	if state.Config.Listen != "0.0.0.0:8443" {
		t.Fatalf("listen = %q", state.Config.Listen)
	}
	user, ok := state.Config.Users["alice-device"]
	if !ok || user.Secret != testSecret || !user.Enabled {
		t.Fatalf("mapped user = %#v", state.Config.Users)
	}
	if _, exists := state.Config.Users["alice@example.test"]; exists {
		t.Fatal("panel email was incorrectly used as GhostLink client ID")
	}
	protected, err := state.ProtectedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(protected), testSecret) {
		t.Fatal("protected config must contain the required runtime secret")
	}
	redacted, err := state.RedactedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), testSecret) ||
		strings.Contains(string(redacted), "alice-device") ||
		strings.Contains(string(redacted), `"secret"`) {
		t.Fatalf("redacted output leaked credentials: %s", redacted)
	}
	if strings.Contains(state.String(), testSecret) {
		t.Fatal("String() leaked the secret")
	}

	second, err := BuildDesiredState(inbound, filepath.Join(filepath.Dir(state.Config.StateDBFile), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	secondProtected, err := second.ProtectedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision != state.Revision || string(secondProtected) != string(protected) {
		t.Fatal("equivalent inbound settings did not produce deterministic desired state")
	}
}

func TestBuildDesiredStateMapsTransportPresetsAndIdentityTLS(t *testing.T) {
	for _, tc := range []struct {
		preset    string
		transport string
		capsule   bool
		cert      bool
	}{
		{preset: PresetH2, transport: TransportH2},
		{preset: PresetH2Capsule, transport: TransportH2, capsule: true},
		{preset: PresetDual, transport: TransportDualMASQUE, cert: true},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			settings := validSettings(t)
			settings.TransportPreset = tc.preset
			settings.IdentityTLS = testIdentityTLS(t)
			if !tc.cert {
				settings.CertificateFile = ""
				settings.PrivateKeyFile = ""
			}
			inbound := &model.Inbound{
				Id: 11, Protocol: model.GhostLink, Enable: true,
				Listen: "0.0.0.0", Port: 28443, Settings: marshalSettings(t, settings),
			}
			state, err := BuildDesiredState(inbound, filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatalf("BuildDesiredState: %v", err)
			}
			if state.Config.Transport != tc.transport || state.Config.EnableH2UDPCapsule != tc.capsule {
				t.Fatalf("transport mapping = %+v", state.Config)
			}
			if state.Config.IdentityTLS == nil ||
				state.Config.IdentityTLS.ServerName != settings.IdentityTLS.ServerName ||
				state.Config.IdentityTLS.ClientID != settings.IdentityTLS.ClientID ||
				state.Config.IdentityTLS.PrivateKey != settings.IdentityTLS.PrivateKey ||
				state.Config.IdentityTLS.Secret != settings.IdentityTLS.Secret {
				t.Fatalf("identity TLS mapping = %+v", state.Config.IdentityTLS)
			}
			protected, err := state.ProtectedJSON()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(protected), `"identity_tls"`) ||
				strings.Contains(string(protected), settings.IdentityTLS.PublicKey) {
				t.Fatalf("protected config identity projection is incorrect: %s", protected)
			}
			redacted, err := state.RedactedJSON()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(redacted), settings.IdentityTLS.PrivateKey) ||
				strings.Contains(string(redacted), settings.IdentityTLS.Secret) {
				t.Fatalf("redacted status leaked node identity: %s", redacted)
			}
		})
	}
}

func TestParseSettingsRejectsIncompleteOrMismatchedIdentityTLS(t *testing.T) {
	settings := validSettings(t)
	settings.TransportPreset = PresetH2
	settings.CertificateFile = ""
	settings.PrivateKeyFile = ""
	if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
		t.Fatal("preset without identityTls was accepted")
	}

	settings.IdentityTLS = testIdentityTLS(t)
	identity, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	settings.IdentityTLS.PublicKey = base64.RawURLEncoding.EncodeToString(identity.PublicKey().Bytes())
	if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
		t.Fatal("mismatched identity public key was accepted")
	}

	settings.IdentityTLS = testIdentityTLS(t)
	settings.IdentityTLS.ShortID = "0011"
	if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
		t.Fatal("short identity shortId was accepted")
	}
}

func TestValidateClientRejectsUnsupportedGhostLinkBusinessModes(t *testing.T) {
	base := model.Client{
		Email: "alice@example.test", ID: "alice-device", Secret: testSecret,
		Enable: true, ExpiryTime: time.Now().Add(time.Hour).UnixMilli(),
	}
	if err := ValidateClient(&base); err != nil {
		t.Fatalf("valid absolute policy rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*model.Client)
		want   string
	}{
		{name: "negative expiry", mutate: func(c *model.Client) { c.ExpiryTime = -time.Hour.Milliseconds() }, want: "delayed-start"},
		{name: "day auto renew", mutate: func(c *model.Client) { c.Reset = 7 }, want: "auto-renew"},
		{name: "monthly auto renew", mutate: func(c *model.Client) { c.ResetDay = 15 }, want: "auto-renew"},
		{name: "weekly auto renew", mutate: func(c *model.Client) { c.ResetWeekday = 3 }, want: "auto-renew"},
		{name: "invalid traffic reset", mutate: func(c *model.Client) { c.TrafficReset = "yearly" }, want: "trafficReset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := base
			tc.mutate(&client)
			err := ValidateClient(&client)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateClient(%s) = %v", tc.name, err)
			}
		})
	}
	base.TrafficReset = "monthly"
	base.TrafficResetDay = 31
	if err := ValidateClient(&base); err != nil {
		t.Fatalf("supported monthly traffic reset rejected: %v", err)
	}
}

func TestBuildDesiredStateWithPoliciesCarriesRuntimeCeiling(t *testing.T) {
	settings := validSettings(t)
	inbound := &model.Inbound{
		Id: 1, Protocol: model.GhostLink, Enable: true, Listen: "127.0.0.1", Port: 8443,
		Settings: marshalSettings(t, settings),
	}
	state, err := BuildDesiredStateWithPolicies(
		inbound,
		filepath.Join(t.TempDir(), "state.db"),
		uint32(os.Geteuid()),
		DefaultControlSocketPath,
		false,
		map[string]RuntimePolicy{
			"alice-device": {
				Enabled: true, MaxTrafficBytes: 123456,
				ExpiresAtUnixMilli: 1893456000000,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	user := state.Config.Users["alice-device"]
	if user.MaxTrafficBytes != 123456 || !user.Enabled ||
		user.ExpiresAtUnixMilli != 1893456000000 || user.PolicyVersion != 1 {
		t.Fatalf("runtime policy user = %+v", user)
	}
}

func TestBuildDesiredStateWaitsWithoutEnabledUsers(t *testing.T) {
	settings := validSettings(t)
	settings.Clients[0].Enable = false
	inbound := &model.Inbound{
		Id:       9,
		Protocol: model.GhostLink,
		Enable:   true,
		Listen:   "::",
		Port:     9443,
		Settings: marshalSettings(t, settings),
	}
	state, err := BuildDesiredState(inbound, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if state.ShouldRun || state.Reason != "waiting_for_enabled_users" {
		t.Fatalf("state = %#v", state)
	}
	if state.Config.Listen != "[::]:9443" {
		t.Fatalf("IPv6 listen = %q", state.Config.Listen)
	}
}

func TestParseSettingsRejectsUnknownFieldsWithoutLeakingSecret(t *testing.T) {
	settings := validSettings(t)
	raw := marshalSettings(t, settings)
	raw = strings.Replace(raw, `"version":1`, `"version":1,"xray":true`, 1)
	_, err := ParseSettings(raw)
	if err == nil {
		t.Fatal("unknown field was accepted")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatalf("parse error leaked secret: %v", err)
	}
}

func TestParseSettingsRejectsInvalidCredentialsAndDuplicateIdentity(t *testing.T) {
	settings := validSettings(t)
	settings.Clients[0].ID = "bad:id"
	if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
		t.Fatal("colon in ClientID was accepted")
	}

	settings = validSettings(t)
	settings.Clients[0].Secret = "short"
	if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
		t.Fatal("short secret was accepted")
	}

	settings = validSettings(t)
	settings.Clients = append(settings.Clients, settings.Clients[0])
	if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
		t.Fatal("duplicate client identity was accepted")
	}
}

func TestParseSettingsRejectsUnsafeWebBackend(t *testing.T) {
	for _, backend := range []string{
		"https://127.0.0.1:8080",
		"http://192.168.1.2:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:8080/path",
		"http://user@127.0.0.1:8080",
	} {
		settings := validSettings(t)
		settings.WebBackendURL = backend
		if _, err := ParseSettings(marshalSettings(t, settings)); err == nil {
			t.Errorf("unsafe backend %q was accepted", backend)
		}
	}
}

func TestBuildDesiredStateRejectsNodeScopeAndRelativeStatePath(t *testing.T) {
	settings := validSettings(t)
	nodeID := 3
	inbound := &model.Inbound{
		Protocol: model.GhostLink,
		NodeID:   &nodeID,
		Enable:   true,
		Port:     8443,
		Settings: marshalSettings(t, settings),
	}
	if _, err := BuildDesiredState(inbound, filepath.Join(t.TempDir(), "state.db")); err == nil {
		t.Fatal("node-scoped GhostLink inbound was accepted")
	}
	inbound.NodeID = nil
	if _, err := BuildDesiredState(inbound, "relative/state.db"); err == nil {
		t.Fatal("relative state database path was accepted")
	}
}

func TestIdentityTLSTargetAddressValidationAndPassthrough(t *testing.T) {
	settings := validSettings(t)
	settings.TransportPreset = PresetH2Capsule
	settings.CertificateFile = ""
	settings.PrivateKeyFile = ""
	settings.IdentityTLS = testIdentityTLS(t)
	settings.IdentityTLS.TargetAddress = "127.0.0.1:8443"

	inbound := &model.Inbound{
		Id:       12,
		Protocol: model.GhostLink,
		Enable:   true,
		Listen:   "0.0.0.0",
		Port:     443,
		Settings: marshalSettings(t, settings),
	}
	state, err := BuildDesiredState(inbound, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("valid targetAddress rejected: %v", err)
	}
	if state.Config.IdentityTLS == nil || state.Config.IdentityTLS.TargetAddress != "127.0.0.1:8443" {
		t.Fatalf("TargetAddress not passed through: %#v", state.Config.IdentityTLS)
	}
	protected, err := state.ProtectedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(protected), `"target_address": "127.0.0.1:8443"`) {
		t.Fatalf("protected JSON missing target_address: %s", protected)
	}

	// Empty TargetAddress must remain omitted.
	settings.IdentityTLS.TargetAddress = ""
	inbound.Settings = marshalSettings(t, settings)
	state, err = BuildDesiredState(inbound, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("empty targetAddress rejected: %v", err)
	}
	protected, err = state.ProtectedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(protected), "target_address") {
		t.Fatalf("empty target_address should be omitted: %s", protected)
	}

	for _, invalid := range []string{
		" 127.0.0.1:8443",
		"127.0.0.1",
		":8443",
		"127.0.0.1:0",
		"127.0.0.1:99999",
		"127.0.0.1:abc",
	} {
		bad := validSettings(t)
		bad.TransportPreset = PresetH2
		bad.CertificateFile = ""
		bad.PrivateKeyFile = ""
		bad.IdentityTLS = testIdentityTLS(t)
		bad.IdentityTLS.TargetAddress = invalid
		if _, err := ParseSettings(marshalSettings(t, bad)); err == nil {
			t.Errorf("invalid targetAddress %q was accepted", invalid)
		}
	}
}
