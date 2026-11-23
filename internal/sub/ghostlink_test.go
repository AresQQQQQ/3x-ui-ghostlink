package sub

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const (
	testGhostLinkClientID = "test-client-id-01"
	testGhostLinkSecret   = "0123456789abcdef0123456789abcdef0123456789abcdef"
	testIdentitySecret    = "ghostlink-node-identity-secret-32"
	testIdentityPrivate   = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	testIdentityPublic    = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw"
)

func seedGhostLinkSubscription(t *testing.T, subID string) *model.Inbound {
	return seedGhostLinkSubscriptionPreset(t, subID, "h2-capsule")
}

func seedGhostLinkSubscriptionPreset(t *testing.T, subID, preset string) *model.Inbound {
	t.Helper()
	initSubDB(t)
	settings := `{
		"version": 1,
		"transportPreset": "` + preset + `",
		"identityTls": {
			"serverName": "www.speedtest.net",
			"targetAddress": "127.0.0.1:8443",
			"clientId": "node-client",
			"secret": "` + testIdentitySecret + `",
			"privateKey": "` + testIdentityPrivate + `",
			"publicKey": "` + testIdentityPublic + `",
			"shortId": "00112233aabbccdd"
		},
		"certificateFile": "/etc/ghostlink/fullchain.pem",
		"privateKeyFile": "/etc/ghostlink/privkey.pem",
		"serverName": "edge.example.com",
		"clients": [{
			"id": "` + testGhostLinkClientID + `",
			"email": "ghost@example.test",
			"secret": "` + testGhostLinkSecret + `",
			"enable": true
		}]
	}`
	inbound := &model.Inbound{
		UserId:       1,
		Tag:          "ghostlink-test",
		Enable:       true,
		Listen:       "0.0.0.0",
		Port:         24443,
		Protocol:     model.GhostLink,
		Remark:       "GhostLink",
		Settings:     settings,
		SubSortIndex: 1,
	}
	db := database.GetDB()
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed GhostLink inbound: %v", err)
	}
	record := &model.ClientRecord{
		Email:  "ghost@example.test",
		SubID:  subID,
		UUID:   testGhostLinkClientID,
		Secret: testGhostLinkSecret,
		Enable: true,
	}
	if err := db.Create(record).Error; err != nil {
		t.Fatalf("seed GhostLink client: %v", err)
	}
	if err := db.Create(&model.ClientInbound{
		ClientId:  record.Id,
		InboundId: inbound.Id,
	}).Error; err != nil {
		t.Fatalf("seed GhostLink client mapping: %v", err)
	}
	watermark := &model.GhostLinkUsageWatermark{
		InboundId:        inbound.Id,
		ClientId:         testGhostLinkClientID,
		Email:            record.Email,
		StoreId:          "test-store",
		State:            "ok",
		ManualEnabled:    true,
		EffectiveEnabled: true,
		PolicyVersion:    1,
		PolicyState:      "ok",
		QuotaBytes:       10 << 30,
		MaxTrafficBytes:  10 << 30,
		ExpiryTime:       time.Now().Add(time.Hour).UnixMilli(),
	}
	if err := db.Create(watermark).Error; err != nil {
		t.Fatalf("seed GhostLink watermark: %v", err)
	}
	return inbound
}

func TestGhostLinkClashSubscriptionUsesNativeOutbound(t *testing.T) {
	seedGhostLinkSubscription(t, "ghost-sub")
	output, _, err := NewSubClashService(false, "", false, NewSubService("")).
		GetClash("ghost-sub", "sub.example.com")
	if err != nil {
		t.Fatalf("GetClash: %v", err)
	}
	for _, want := range []string{
		"type: ghostlink",
		"server: sub.example.com",
		"port: 24443",
		"client-id: " + testGhostLinkClientID,
		"secret: " + testGhostLinkSecret,
		"server-name: edge.example.com",
		"sni: www.speedtest.net",
		"identity-client-id: node-client",
		"identity-secret: " + testIdentitySecret,
		"identity-public-key: " + testIdentityPublic,
		"identity-short-id: 00112233aabbccdd",
		"h2-scale-threshold: 4",
		"transport: h2-capsule",
		"early-data: true",
		"enable-udp-capsule: true",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Clash YAML missing %q:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{
		"/etc/ghostlink/fullchain.pem",
		"/etc/ghostlink/privkey.pem",
		"127.0.0.1:8443",
		"target-address",
		"targetAddress",
		testIdentityPrivate,
		"type: socks5",
		"type: vless",
		"type: masque",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("Clash YAML contains forbidden %q:\n%s", forbidden, output)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(output), &document); err != nil {
		t.Fatalf("parse Mihomo YAML: %v", err)
	}
	proxies, _ := document["proxies"].([]any)
	if len(proxies) != 1 {
		t.Fatalf("parsed proxies = %#v, want one GhostLink outbound", document["proxies"])
	}
	proxy, _ := proxies[0].(map[string]any)
	allowed := map[string]bool{
		"name": true, "type": true, "server": true, "port": true, "transport": true,
		"client-id": true, "secret": true, "server-name": true,
		"early-data": true, "enable-udp-capsule": true, "ca-file": true,
		"failover-cooldown-seconds": true, "max-udp-associations": true,
		"sni": true, "h2-scale-threshold": true, "h2-idle-timeout-seconds": true,
		"identity-client-id": true, "identity-secret": true,
		"identity-public-key": true, "identity-short-id": true,
	}
	for field := range proxy {
		if !allowed[field] {
			t.Fatalf("unexpected Mihomo GhostLink field %q: %#v", field, proxy)
		}
	}
}

func TestGhostLinkSubscriptionTransportPresets(t *testing.T) {
	for _, tc := range []struct {
		preset    string
		capsule   bool
		earlyData bool
	}{
		{preset: "h2", capsule: false, earlyData: true},
		{preset: "h2-capsule", capsule: true, earlyData: true},
		{preset: "dual", capsule: false, earlyData: false},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			subID := "ghost-preset-" + tc.preset
			seedGhostLinkSubscriptionPreset(t, subID, tc.preset)
			output, _, err := NewSubClashService(false, "", false, NewSubService("")).
				GetClash(subID, "sub.example.com")
			if err != nil {
				t.Fatalf("GetClash: %v", err)
			}
			proxy := firstClashProxy(t, output)
			if proxy["transport"] != tc.preset {
				t.Fatalf("transport = %v, want %v", proxy["transport"], tc.preset)
			}
			if proxy["enable-udp-capsule"] != tc.capsule {
				t.Fatalf("enable-udp-capsule = %v, want %v", proxy["enable-udp-capsule"], tc.capsule)
			}
			gotEarly, _ := proxy["early-data"].(bool)
			if gotEarly != tc.earlyData {
				t.Fatalf("early-data = %v, want %v", proxy["early-data"], tc.earlyData)
			}
			if fmt.Sprint(proxy["h2-scale-threshold"]) != "4" {
				t.Fatalf("h2-scale-threshold = %v", proxy["h2-scale-threshold"])
			}
			if proxy["identity-public-key"] != testIdentityPublic ||
				proxy["identity-client-id"] != "node-client" ||
				proxy["sni"] != "www.speedtest.net" {
				t.Fatalf("identity projection = %#v", proxy)
			}
			if strings.Contains(output, testIdentityPrivate) {
				t.Fatalf("subscription leaked identity private key:\n%s", output)
			}
		})
	}
}

func TestGhostLinkLegacySubscriptionDefaultsToDualWithoutCapsule(t *testing.T) {
	inbound := seedGhostLinkSubscription(t, "ghost-legacy-default")
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatal(err)
	}
	delete(settings, "transportPreset")
	delete(settings, "identityTls")
	legacy, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.GetDB().Model(&model.Inbound{}).
		Where("id = ?", inbound.Id).
		Update("settings", string(legacy)).Error; err != nil {
		t.Fatal(err)
	}
	output, _, err := NewSubClashService(false, "", false, NewSubService("")).
		GetClash("ghost-legacy-default", "sub.example.com")
	if err != nil {
		t.Fatalf("GetClash: %v", err)
	}
	proxy := firstClashProxy(t, output)
	if proxy["enable-udp-capsule"] != false ||
		fmt.Sprint(proxy["h2-scale-threshold"]) != "4" {
		t.Fatalf("legacy subscription defaults = %#v", proxy)
	}
	for _, field := range []string{
		"identity-client-id", "identity-secret", "identity-public-key", "identity-short-id",
	} {
		if _, exists := proxy[field]; exists {
			t.Fatalf("legacy subscription fabricated %s: %#v", field, proxy)
		}
	}
}

func TestGhostLinkClashAdvertisedEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		listen     string
		strategy   string
		shareAddr  string
		wantServer string
	}{
		{name: "listen strategy public", listen: "203.0.113.7", strategy: "listen", wantServer: "203.0.113.7"},
		{name: "node strategy local falls back to public listen", listen: "edge.listen", strategy: "node", wantServer: "edge.listen"},
		{name: "custom strategy", listen: "203.0.113.7", strategy: "custom", shareAddr: "edge.public", wantServer: "edge.public"},
		{name: "wildcard listen", listen: "0.0.0.0", strategy: "listen", wantServer: "sub.example.com"},
		{name: "IPv6 wildcard listen", listen: "::", strategy: "listen", wantServer: "sub.example.com"},
		{name: "private listen", listen: "192.168.2.10", strategy: "listen", wantServer: "192.168.2.10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inbound := seedGhostLinkSubscription(t, "ghost-endpoint-"+strings.ReplaceAll(tc.name, " ", "-"))
			if err := database.GetDB().Model(&model.Inbound{}).
				Where("id = ?", inbound.Id).
				Updates(map[string]any{
					"listen":              tc.listen,
					"share_addr_strategy": tc.strategy,
					"share_addr":          tc.shareAddr,
				}).Error; err != nil {
				t.Fatalf("update endpoint fields: %v", err)
			}
			output, _, err := NewSubClashService(false, "", false, NewSubService("")).
				GetClash("ghost-endpoint-"+strings.ReplaceAll(tc.name, " ", "-"), "sub.example.com")
			if err != nil {
				t.Fatalf("GetClash: %v", err)
			}
			proxy := firstClashProxy(t, output)
			if proxy["server"] != tc.wantServer || fmt.Sprint(proxy["port"]) != "24443" {
				t.Fatalf("endpoint = %v:%v, want %s:24443", proxy["server"], proxy["port"], tc.wantServer)
			}
			if proxy["server"] == "0.0.0.0" || proxy["server"] == "::" {
				t.Fatalf("bind wildcard leaked into subscription: %#v", proxy)
			}
		})
	}
}

func TestGhostLinkClashHostEndpointOverride(t *testing.T) {
	inbound := seedGhostLinkSubscription(t, "ghost-host-endpoint")
	host := &model.Host{
		InboundId: inbound.Id,
		Address:   "host.edge.example",
		Port:      8443,
		Remark:    "public-host",
	}
	if err := database.GetDB().Create(host).Error; err != nil {
		t.Fatalf("seed host endpoint: %v", err)
	}
	output, _, err := NewSubClashService(false, "", false, NewSubService("")).
		GetClash("ghost-host-endpoint", "sub.example.com")
	if err != nil {
		t.Fatalf("GetClash: %v", err)
	}
	proxy := firstClashProxy(t, output)
	if proxy["server"] != "host.edge.example" || fmt.Sprint(proxy["port"]) != "8443" {
		t.Fatalf("host endpoint = %v:%v, want host.edge.example:8443", proxy["server"], proxy["port"])
	}
	if proxy["server-name"] != "edge.example.com" {
		t.Fatalf("server-name = %v, want GhostLink settings value", proxy["server-name"])
	}
	if _, exists := proxy["skip-cert-verify"]; exists {
		t.Fatalf("TLS verification must not be disabled: %#v", proxy)
	}
}

func TestGhostLinkSubscriptionRejectsNodeManagedInbound(t *testing.T) {
	inbound := seedGhostLinkSubscription(t, "ghost-node-managed")
	nodeID := 7
	if err := database.GetDB().Model(&model.Inbound{}).
		Where("id = ?", inbound.Id).
		Update("node_id", nodeID).Error; err != nil {
		t.Fatalf("mark node-managed: %v", err)
	}
	_, _, err := NewSubClashService(false, "", false, NewSubService("")).
		GetClash("ghost-node-managed", "sub.example.com")
	if err == nil || !strings.Contains(err.Error(), "local-only") {
		t.Fatalf("node-managed GhostLink error = %v", err)
	}
}

func TestGhostLinkClashYAMLContractFixture(t *testing.T) {
	seedGhostLinkSubscription(t, "ghost-contract")
	output, _, err := NewSubClashService(false, "", false, NewSubService("")).
		GetClash("ghost-contract", "sub.example.com")
	if err != nil {
		t.Fatalf("GetClash: %v", err)
	}
	fixturePath := filepath.Join("testdata", "ghostlink-mihomo-contract.yaml")
	if os.Getenv("GHOSTLINK_CONTRACT_UPDATE") == "1" {
		if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(fixturePath, []byte(output), 0o644); err != nil {
			t.Fatalf("write contract fixture: %v", err)
		}
	}
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read contract fixture: %v", err)
	}
	if strings.TrimSpace(output) != strings.TrimSpace(string(fixture)) {
		t.Fatalf("generated Mihomo YAML differs from reviewed contract fixture:\n%s", output)
	}
}

func firstClashProxy(t *testing.T, output string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(output), &document); err != nil {
		t.Fatalf("parse Mihomo YAML: %v", err)
	}
	proxies, _ := document["proxies"].([]any)
	if len(proxies) != 1 {
		t.Fatalf("parsed proxies = %#v, want one", document["proxies"])
	}
	proxy, _ := proxies[0].(map[string]any)
	if proxy == nil {
		t.Fatalf("first proxy has unexpected type %T", proxies[0])
	}
	return proxy
}

func TestGhostLinkSubscriptionFailsClosedOutsideMihomoYAML(t *testing.T) {
	seedGhostLinkSubscription(t, "ghost-format")
	if _, _, _, _, err := NewSubService("").GetSubs("ghost-format", "sub.example.com"); !errors.Is(err, errGhostLinkMihomoOnly) {
		t.Fatalf("standard subscription error = %v, want unsupported-format", err)
	}
	if _, _, err := NewSubJsonService("", "", "", "", NewSubService("")).
		GetJson("ghost-format", "sub.example.com", false); !errors.Is(err, errGhostLinkMihomoOnly) {
		t.Fatalf("JSON subscription error = %v, want unsupported-format", err)
	}
	inbound := &model.Inbound{Protocol: model.GhostLink}
	if link := NewSubService("").GetLink(inbound, "ghost@example.test"); link != "" {
		t.Fatalf("GetLink = %q, want no fabricated standard URI", link)
	}
}

func TestGhostLinkSubscriptionPolicyFilter(t *testing.T) {
	inbound := seedGhostLinkSubscription(t, "ghost-policy")
	tests := []struct {
		name       string
		update     map[string]any
		wantOutput bool
	}{
		{name: "effective", update: nil, wantOutput: true},
		{name: "pending usage", update: map[string]any{"state": "pending", "error_code": "store_epoch_changed"}},
		{name: "manual state mismatch", update: map[string]any{"manual_enabled": false}},
		{name: "quota exhausted", update: map[string]any{"policy_state": "quota_exhausted", "effective_enabled": false}},
		{name: "manual disabled", update: map[string]any{"policy_state": "manual_disabled", "effective_enabled": false}},
		{name: "expired", update: map[string]any{"policy_state": "expired", "effective_enabled": false}},
	}
	db := database.GetDB()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := db.Model(&model.GhostLinkUsageWatermark{}).
				Where("inbound_id = ?", inbound.Id).
				Updates(map[string]any{
					"state":             "ok",
					"error_code":        "",
					"policy_state":      "ok",
					"policy_error_code": "",
					"manual_enabled":    true,
					"effective_enabled": true,
				}).Error; err != nil {
				t.Fatalf("reset watermark: %v", err)
			}
			if tc.update != nil {
				if err := db.Model(&model.GhostLinkUsageWatermark{}).
					Where("inbound_id = ?", inbound.Id).
					Updates(tc.update).Error; err != nil {
					t.Fatalf("update watermark: %v", err)
				}
			}
			output, _, err := NewSubClashService(false, "", false, NewSubService("")).
				GetClash("ghost-policy", "sub.example.com")
			if err != nil {
				t.Fatalf("GetClash: %v", err)
			}
			if got := strings.Contains(output, "type: ghostlink"); got != tc.wantOutput {
				t.Fatalf("ghostlink emitted = %t, want %t; output:\n%s", got, tc.wantOutput, output)
			}
		})
	}
	if err := db.Where("inbound_id = ?", inbound.Id).
		Delete(&model.GhostLinkUsageWatermark{}).Error; err != nil {
		t.Fatalf("delete watermark: %v", err)
	}
	output, _, err := NewSubClashService(false, "", false, NewSubService("")).
		GetClash("ghost-policy", "sub.example.com")
	if err != nil {
		t.Fatalf("GetClash without watermark: %v", err)
	}
	if strings.Contains(output, "type: ghostlink") {
		t.Fatalf("missing watermark emitted credentials:\n%s", output)
	}
}

func TestLegacyClashPreservesGhostLinkCustomType(t *testing.T) {
	proxy := map[string]any{
		"name": "ghost", "type": "ghostlink", "server": "edge.example.com", "port": 443,
		"client-id": "client", "secret": testGhostLinkSecret,
		"server-name": "edge.example.com", "sni": "www.speedtest.net",
		"h2-scale-threshold": 4, "enable-udp-capsule": true,
		"identity-client-id": "node-client", "identity-secret": testIdentitySecret,
		"identity-public-key": testIdentityPublic, "identity-short-id": "00112233aabbccdd",
		"unknown": "drop",
	}
	got := legacyClashProxy(proxy)
	if got == nil || got["type"] != "ghostlink" || got["enable-udp-capsule"] != true ||
		got["h2-scale-threshold"] != 4 || got["identity-public-key"] != testIdentityPublic {
		t.Fatalf("legacy GhostLink proxy was filtered: %#v", got)
	}
	if _, exists := got["unknown"]; exists {
		t.Fatalf("unknown field leaked through legacy filter: %#v", got)
	}
}
