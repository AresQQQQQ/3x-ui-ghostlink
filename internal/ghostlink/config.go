// Package ghostlink defines the 3x-ui-owned configuration contract for a
// GhostLink inbound and its installation and lifecycle.
package ghostlink

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const (
	SchemaVersion       = 1
	TransportH2         = "h2"
	TransportDualMASQUE = "masque-dual"
	PresetH2            = "h2"
	PresetH2Capsule     = "h2-capsule"
	PresetDual          = "dual"
	MinClientSecretSize = 32
	MaxClientSecretSize = 1024
	IdentitySecretSize  = 32
	ShortIDSize         = 8
	DefaultH2Scale      = 4
)

// TransportMapping is the fixed translation from the simple panel preset to
// the server fields understood by GhostLink Core.
type TransportMapping struct {
	Preset             string
	CoreTransport      string
	EnableH2UDPCapsule bool
	RequireCertificate bool
}

// ResolveTransportPreset maps the three user-facing GhostLink presets. An
// empty value is reserved for Round 1-9 records and keeps their dual listener
// behavior.
func ResolveTransportPreset(preset string) (TransportMapping, error) {
	if strings.TrimSpace(preset) != preset {
		return TransportMapping{}, errors.New("GhostLink transportPreset must not contain surrounding whitespace")
	}
	switch preset {
	case "":
		return TransportMapping{CoreTransport: TransportDualMASQUE, RequireCertificate: true}, nil
	case PresetH2:
		return TransportMapping{Preset: PresetH2, CoreTransport: TransportH2}, nil
	case PresetH2Capsule:
		return TransportMapping{
			Preset: PresetH2Capsule, CoreTransport: TransportH2, EnableH2UDPCapsule: true,
		}, nil
	case PresetDual:
		return TransportMapping{
			Preset: PresetDual, CoreTransport: TransportDualMASQUE, RequireCertificate: true,
		}, nil
	default:
		return TransportMapping{}, fmt.Errorf("unsupported GhostLink transportPreset %q", preset)
	}
}

// IdentityTLSConfig is the panel-owned REALITY-like node identity. PublicKey
// is delivered in subscriptions; PrivateKey and TargetAddress remain inside
// ghostlinkd config.
type IdentityTLSConfig struct {
	ServerName    string `json:"serverName"`
	TargetAddress string `json:"targetAddress,omitempty"`
	ClientID      string `json:"clientId"`
	Secret        string `json:"secret"`
	PublicKey     string `json:"publicKey"`
	PrivateKey    string `json:"privateKey"`
	ShortID       string `json:"shortId"`
}

// Settings is the protocol-specific object stored in Inbound.Settings.
//
// The existing 3x-ui client fields are used deliberately:
//   - model.Client.ID maps to GhostLink ClientID.
//   - model.Client.Secret maps to GhostLink Secret.
//   - model.Client.Email is the panel identity and is not sent to ghostlinkd.
//   - model.Client.Enable controls whether the desired user is enabled.
type Settings struct {
	Version         int                `json:"version"`
	TransportPreset string             `json:"transportPreset,omitempty"`
	IdentityTLS     *IdentityTLSConfig `json:"identityTls,omitempty"`
	CertificateFile string             `json:"certificateFile"`
	PrivateKeyFile  string             `json:"privateKeyFile"`
	ServerName      string             `json:"serverName,omitempty"`
	WebBackendURL   string             `json:"webBackendUrl,omitempty"`
	Clients         []model.Client     `json:"clients"`
}

// Match the field order used by the LocalControl wire and Core revision.
type desiredUser = RuntimeUser

// RuntimePolicy is the effective policy applied to one Core user. It is
// derived from the panel business fields and durable accounting metadata.
type RuntimePolicy struct {
	Enabled            bool
	MaxTrafficBytes    uint64
	ExpiresAtUnixMilli int64
}

// ManagementConfig mirrors the JSON fields consumed by
// management/cmd/ghostlinkd. Keep unknown metadata out of this structure so it
// can be passed directly to ghostlinkd's strict decoder.
type ManagementConfig struct {
	Transport           string                 `json:"transport"`
	EnableH2UDPCapsule  bool                   `json:"enable_h2_udp_capsule,omitempty"`
	Listen              string                 `json:"listen"`
	WebBackendURL       string                 `json:"web_backend_url,omitempty"`
	TLSCertFile         string                 `json:"tls_cert_file"`
	TLSKeyFile          string                 `json:"tls_key_file"`
	StateDBFile         string                 `json:"state_db_file"`
	LogLevel            string                 `json:"log_level"`
	AllowPrivateTargets bool                   `json:"allow_private_targets"`
	MaxConnections      int                    `json:"max_connections"`
	MaxTCPStreams       int                    `json:"max_tcp_streams"`
	MaxTotalTCPStreams  int                    `json:"max_total_tcp_streams"`
	MaxUDPRoutes        int                    `json:"max_udp_routes"`
	MaxTotalUDPRoutes   int                    `json:"max_total_udp_routes"`
	UDPIdleSeconds      int                    `json:"udp_idle_seconds"`
	HandshakeSeconds    int                    `json:"handshake_seconds"`
	TargetDialSeconds   int                    `json:"target_dial_timeout_seconds"`
	PolicyVersion       int                    `json:"policy_version"`
	IdentityTLS         *ManagementIdentityTLS `json:"identity_tls,omitempty"`
	Users               map[string]desiredUser `json:"users"`
	LocalControl        *LocalControlConfig    `json:"local_control,omitempty"`
}

type ManagementIdentityTLS struct {
	ServerName    string `json:"server_name"`
	TargetAddress string `json:"target_address,omitempty"`
	ClientID      string `json:"client_id"`
	Secret        string `json:"secret"`
	PrivateKey    string `json:"private_key"`
	ShortID       string `json:"short_id"`
}

type LocalControlConfig struct {
	PeerUID    uint32 `json:"peer_uid"`
	SocketPath string `json:"socket_path,omitempty"`
}

// DesiredState is internal management metadata plus the exact config handed to
// the one supervised GhostLink process.
type DesiredState struct {
	InboundID    int
	Revision     string
	UserRevision string
	ServerName   string
	ShouldRun    bool
	Reason       string
	UserCount    int
	EnabledUsers int
	Config       ManagementConfig
}

type RedactedSummary struct {
	InboundID    int    `json:"inbound_id"`
	Revision     string `json:"revision"`
	UserRevision string `json:"user_revision"`
	ServerName   string `json:"server_name,omitempty"`
	Listen       string `json:"listen"`
	ShouldRun    bool   `json:"should_run"`
	Reason       string `json:"reason"`
	UserCount    int    `json:"user_count"`
	EnabledUsers int    `json:"enabled_users"`
}

// ParseSettings applies the GhostLink-specific schema and rejects unknown
// fields rather than silently accepting Xray or MTProto configuration.
func ParseSettings(raw string) (Settings, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var settings Settings
	if err := decoder.Decode(&settings); err != nil {
		return Settings{}, fmt.Errorf("invalid GhostLink settings: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Settings{}, errors.New("GhostLink settings must contain exactly one JSON object")
	}
	if settings.Version != SchemaVersion {
		return Settings{}, fmt.Errorf("GhostLink settings version must be %d", SchemaVersion)
	}
	transport, err := ResolveTransportPreset(settings.TransportPreset)
	if err != nil {
		return Settings{}, err
	}
	if transport.Preset != "" && settings.IdentityTLS == nil {
		return Settings{}, errors.New("GhostLink transportPreset requires complete identityTls credentials")
	}
	if settings.IdentityTLS != nil {
		if err := validateIdentityTLS(settings.IdentityTLS); err != nil {
			return Settings{}, err
		}
	}
	hasCertificate := settings.CertificateFile != "" || settings.PrivateKeyFile != ""
	if transport.RequireCertificate && !hasCertificate {
		return Settings{}, errors.New("GhostLink certificateFile and privateKeyFile are required for the dual-stack preset")
	}
	if hasCertificate {
		if strings.TrimSpace(settings.CertificateFile) == "" ||
			strings.TrimSpace(settings.PrivateKeyFile) == "" {
			return Settings{}, errors.New("GhostLink certificateFile and privateKeyFile must be provided together")
		}
		if !filepath.IsAbs(settings.CertificateFile) ||
			!filepath.IsAbs(settings.PrivateKeyFile) {
			return Settings{}, errors.New("GhostLink certificateFile and privateKeyFile must be absolute paths")
		}
		settings.CertificateFile = filepath.Clean(settings.CertificateFile)
		settings.PrivateKeyFile = filepath.Clean(settings.PrivateKeyFile)
		if err := validateCertificate(settings); err != nil {
			return Settings{}, err
		}
	} else {
		settings.CertificateFile = ""
		settings.PrivateKeyFile = ""
	}
	if err := validateWebBackendURL(settings.WebBackendURL); err != nil {
		return Settings{}, err
	}
	seenEmails := make(map[string]struct{}, len(settings.Clients))
	seenIDs := make(map[string]struct{}, len(settings.Clients))
	for i := range settings.Clients {
		client := &settings.Clients[i]
		if err := ValidateClient(client); err != nil {
			return Settings{}, fmt.Errorf("GhostLink client %d: %w", i+1, err)
		}
		emailKey := strings.ToLower(client.Email)
		if _, exists := seenEmails[emailKey]; exists {
			return Settings{}, fmt.Errorf("GhostLink client email is duplicated: %s", client.Email)
		}
		if _, exists := seenIDs[client.ID]; exists {
			return Settings{}, fmt.Errorf("GhostLink client ID is duplicated: %s", client.ID)
		}
		seenEmails[emailKey] = struct{}{}
		seenIDs[client.ID] = struct{}{}
	}
	if settings.IdentityTLS != nil {
		for _, client := range settings.Clients {
			if client.Secret == settings.IdentityTLS.Secret {
				return Settings{}, errors.New("GhostLink identityTls.secret must differ from every user secret")
			}
		}
	}
	return settings, nil
}

// ClientIdentityMap returns the current ClientID-to-email mapping without
// reading certificate files or returning secrets. It is used by usage
// accounting after the runtime has already been validated.
func ClientIdentityMap(inbound *model.Inbound) (map[string]string, error) {
	if inbound == nil || inbound.Protocol != model.GhostLink {
		return nil, errors.New("not a GhostLink inbound")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(inbound.Settings))
	decoder.DisallowUnknownFields()
	var settings Settings
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("invalid GhostLink settings: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("GhostLink settings must contain exactly one JSON object")
	}
	if settings.Version != SchemaVersion {
		return nil, fmt.Errorf("GhostLink settings version must be %d", SchemaVersion)
	}
	identities := make(map[string]string, len(settings.Clients))
	seenEmails := make(map[string]struct{}, len(settings.Clients))
	for i := range settings.Clients {
		client := &settings.Clients[i]
		if err := ValidateClient(client); err != nil {
			return nil, fmt.Errorf("GhostLink client %d: %w", i+1, err)
		}
		emailKey := strings.ToLower(client.Email)
		if _, exists := seenEmails[emailKey]; exists {
			return nil, fmt.Errorf("GhostLink client email is duplicated: %s", client.Email)
		}
		if _, exists := identities[client.ID]; exists {
			return nil, fmt.Errorf("GhostLink client ID is duplicated: %s", client.ID)
		}
		seenEmails[emailKey] = struct{}{}
		identities[client.ID] = client.Email
	}
	return identities, nil
}

func validateCertificate(settings Settings) error {
	pair, err := tls.LoadX509KeyPair(settings.CertificateFile, settings.PrivateKeyFile)
	if err != nil {
		return errors.New("GhostLink certificate and private key are invalid or unreadable")
	}
	if len(pair.Certificate) == 0 {
		return errors.New("GhostLink certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("GhostLink leaf certificate is invalid")
	}
	serverName := strings.TrimSpace(settings.ServerName)
	if serverName != "" {
		if strings.TrimSpace(serverName) != serverName {
			return errors.New("GhostLink serverName must not contain surrounding whitespace")
		}
		if err := leaf.VerifyHostname(serverName); err != nil {
			return fmt.Errorf("GhostLink certificate does not cover serverName %q", serverName)
		}
	}
	return nil
}

func validateIdentityTLS(identity *IdentityTLSConfig) error {
	if identity == nil {
		return errors.New("identityTls is required")
	}
	if err := validateIdentityName("identityTls.serverName", identity.ServerName); err != nil {
		return err
	}
	if err := validateIdentityTargetAddress(identity.TargetAddress); err != nil {
		return err
	}
	if err := validateNodeClientID(identity.ClientID); err != nil {
		return err
	}
	secretSize := len([]byte(identity.Secret))
	if secretSize < IdentitySecretSize || secretSize > MaxClientSecretSize {
		return fmt.Errorf("identityTls.secret must contain %d-%d bytes", IdentitySecretSize, MaxClientSecretSize)
	}
	if strings.TrimSpace(identity.Secret) != identity.Secret {
		return errors.New("identityTls.secret must not contain surrounding whitespace")
	}
	if len(identity.ShortID) != ShortIDSize*2 {
		return fmt.Errorf("identityTls.shortId must be exactly %d hexadecimal characters", ShortIDSize*2)
	}
	if _, err := hex.DecodeString(identity.ShortID); err != nil {
		return errors.New("identityTls.shortId must be hexadecimal")
	}
	privateBytes, err := decodeX25519Key("identityTls.privateKey", identity.PrivateKey)
	if err != nil {
		return err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return errors.New("identityTls.privateKey must be a 32-byte X25519 private key")
	}
	publicBytes, err := decodeX25519Key("identityTls.publicKey", identity.PublicKey)
	if err != nil {
		return err
	}
	if !subtleBytesEqual(publicBytes, privateKey.PublicKey().Bytes()) {
		return errors.New("identityTls.publicKey does not match identityTls.privateKey")
	}
	return nil
}

func decodeX25519Key(field, value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s must be a 32-byte unpadded base64url key", field)
	}
	if _, err := ecdh.X25519().NewPublicKey(raw); err != nil {
		// A private key is also checked by NewPrivateKey at its call site.
		if field != "identityTls.privateKey" {
			return nil, fmt.Errorf("%s is not a valid X25519 key", field)
		}
	}
	return raw, nil
}

func subtleBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func validateIdentityName(field, value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, ":/\\ \t\r\n") {
		return fmt.Errorf("%s must be a hostname without a scheme, port, path or whitespace", field)
	}
	return nil
}

func validateIdentityTargetAddress(value string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) != value {
		return errors.New("identityTls.targetAddress must not contain surrounding whitespace")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("identityTls.targetAddress must be a fixed host:port: %w", err)
	}
	if host == "" {
		return errors.New("identityTls.targetAddress host is empty")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("identityTls.targetAddress port must be between 1 and 65535")
	}
	return nil
}

func validateNodeClientID(value string) error {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return errors.New("identityTls.clientId must be 1-128 characters without surrounding whitespace")
	}
	for _, char := range []byte(value) {
		if char < 0x21 || char > 0x7e || char == ':' {
			return errors.New("identityTls.clientId must contain printable ASCII characters other than ':'")
		}
	}
	return nil
}

// ValidateClient validates the explicit 3x-ui Client to GhostLink credential
// mapping without requiring the inbound-wide certificate and listener fields.
func ValidateClient(client *model.Client) error {
	if client == nil {
		return errors.New("client is nil")
	}
	email := strings.TrimSpace(client.Email)
	if email == "" || email != client.Email {
		return errors.New("email is required without surrounding whitespace")
	}
	if client.ID == "" || len(client.ID) > 128 || strings.TrimSpace(client.ID) != client.ID {
		return errors.New("ID maps to ClientID and must be 1-128 printable ASCII characters without surrounding whitespace")
	}
	for _, value := range []byte(client.ID) {
		if value < 0x21 || value > 0x7e || value == ':' {
			return errors.New("ID maps to ClientID and must contain printable ASCII characters other than ':'")
		}
	}
	secretSize := len([]byte(client.Secret))
	if secretSize < MinClientSecretSize || secretSize > MaxClientSecretSize {
		return fmt.Errorf("secret maps to GhostLink Secret and must contain %d-%d bytes", MinClientSecretSize, MaxClientSecretSize)
	}
	if client.TotalGB < 0 {
		return errors.New("totalGB must not be negative")
	}
	if client.ExpiryTime < 0 {
		return errors.New("delayed-start negative expiryTime is not supported for GhostLink; use an absolute expiry timestamp")
	}
	if client.Reset != 0 || client.ResetDay != 0 || client.ResetWeekday != 0 || client.ResetMax != 0 {
		return errors.New("reset/resetDay/resetWeekday/resetMax auto-renew is not supported for GhostLink; use trafficReset")
	}
	switch client.TrafficReset {
	case "", "never", "hourly", "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("trafficReset must be never, hourly, daily, weekly or monthly, got %q", client.TrafficReset)
	}
	if client.TrafficResetDay < 0 || client.TrafficResetDay > 31 {
		return errors.New("trafficResetDay must be between 0 and 31")
	}
	return nil
}

func validateWebBackendURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("webBackendUrl must be a plain loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return errors.New("webBackendUrl requires an explicit loopback IP and port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("webBackendUrl has an invalid TCP port")
	}
	return nil
}

func normalizeInbound(inbound *model.Inbound) (Settings, string, error) {
	if inbound == nil {
		return Settings{}, "", errors.New("GhostLink inbound is nil")
	}
	if inbound.Protocol != model.GhostLink {
		return Settings{}, "", fmt.Errorf("inbound protocol %q is not GhostLink", inbound.Protocol)
	}
	if inbound.NodeID != nil {
		return Settings{}, "", errors.New("GhostLink is local-only in the first integration version")
	}
	if strings.TrimSpace(inbound.StreamSettings) != "" {
		return Settings{}, "", errors.New("GhostLink does not use Xray streamSettings; configure TLS in GhostLink settings")
	}
	if strings.TrimSpace(inbound.Sniffing) != "" {
		return Settings{}, "", errors.New("GhostLink does not use Xray sniffing settings")
	}
	if inbound.Port < 1 || inbound.Port > 65535 {
		return Settings{}, "", errors.New("GhostLink port must be between 1 and 65535")
	}
	listenIP := strings.TrimSpace(inbound.Listen)
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	if net.ParseIP(listenIP) == nil {
		return Settings{}, "", errors.New("GhostLink listen must be an explicit IP address")
	}
	settings, err := ParseSettings(inbound.Settings)
	if err != nil {
		return Settings{}, "", err
	}
	return settings, listenIP, nil
}

// ValidateInbound validates the model-level contract without requiring
// supervisor-owned paths.
func ValidateInbound(inbound *model.Inbound) error {
	_, _, err := normalizeInbound(inbound)
	return err
}

// BuildDesiredState validates the inbound and creates a deterministic,
// secret-bearing config for a future authenticated single-process supervisor.
func BuildDesiredState(inbound *model.Inbound, stateDBFile string) (DesiredState, error) {
	peerUID := uint32(0)
	if uid := os.Geteuid(); uid >= 0 {
		peerUID = uint32(uid)
	}
	return BuildDesiredStateWithControl(inbound, stateDBFile, peerUID, DefaultControlSocketPath)
}

// BuildDesiredStateWithControl is the fixed control-identity seam used by the
// systemd controller and Linux smoke tests.
func BuildDesiredStateWithControl(inbound *model.Inbound, stateDBFile string, peerUID uint32, socketPath string) (DesiredState, error) {
	return BuildDesiredStateWithOptions(inbound, stateDBFile, peerUID, socketPath, false)
}

// BuildDesiredStateWithOptions is a narrow test seam. Production callers keep
// private targets disabled.
func BuildDesiredStateWithOptions(
	inbound *model.Inbound,
	stateDBFile string,
	peerUID uint32,
	socketPath string,
	allowPrivateTargets bool,
) (DesiredState, error) {
	return buildDesiredStateWithPolicies(
		inbound,
		stateDBFile,
		peerUID,
		socketPath,
		allowPrivateTargets,
		nil,
	)
}

func BuildDesiredStateWithPolicies(
	inbound *model.Inbound,
	stateDBFile string,
	peerUID uint32,
	socketPath string,
	allowPrivateTargets bool,
	policies map[string]RuntimePolicy,
) (DesiredState, error) {
	return buildDesiredStateWithPolicies(
		inbound,
		stateDBFile,
		peerUID,
		socketPath,
		allowPrivateTargets,
		policies,
	)
}

func buildDesiredStateWithPolicies(
	inbound *model.Inbound,
	stateDBFile string,
	peerUID uint32,
	socketPath string,
	allowPrivateTargets bool,
	policies map[string]RuntimePolicy,
) (DesiredState, error) {
	if !filepath.IsAbs(stateDBFile) {
		return DesiredState{}, errors.New("GhostLink state database path must be absolute")
	}
	if socketPath == "" {
		socketPath = DefaultControlSocketPath
	}
	if !strings.HasPrefix(socketPath, "/") || pathpkg.Clean(socketPath) != socketPath {
		return DesiredState{}, errors.New("GhostLink local control socket path must be absolute and clean")
	}
	settings, listenIP, err := normalizeInbound(inbound)
	if err != nil {
		return DesiredState{}, err
	}
	transport, err := ResolveTransportPreset(settings.TransportPreset)
	if err != nil {
		return DesiredState{}, err
	}
	users := make(map[string]desiredUser, len(settings.Clients))
	enabledUsers := 0
	for _, client := range settings.Clients {
		policy := RuntimePolicy{Enabled: client.Enable, ExpiresAtUnixMilli: client.ExpiryTime}
		if policies != nil {
			var ok bool
			policy, ok = policies[client.ID]
			if !ok {
				return DesiredState{}, fmt.Errorf("runtime policy is missing for GhostLink client %q", client.ID)
			}
		}
		users[client.ID] = desiredUser{
			Secret:             client.Secret,
			Enabled:            policy.Enabled,
			MaxTrafficBytes:    policy.MaxTrafficBytes,
			ExpiresAtUnixMilli: policy.ExpiresAtUnixMilli,
			PolicyVersion:      1,
			MaxConnections:     -1,
			MaxTCPStreams:      -1,
			MaxUDPRoutes:       -1,
		}
		if policy.Enabled {
			enabledUsers++
		}
	}
	if policies != nil && len(policies) != len(settings.Clients) {
		return DesiredState{}, errors.New("runtime policy set does not match the GhostLink client set")
	}
	config := ManagementConfig{
		Transport:           transport.CoreTransport,
		EnableH2UDPCapsule:  transport.EnableH2UDPCapsule,
		Listen:              net.JoinHostPort(listenIP, strconv.Itoa(inbound.Port)),
		WebBackendURL:       canonicalWebBackendURL(settings.WebBackendURL),
		TLSCertFile:         settings.CertificateFile,
		TLSKeyFile:          settings.PrivateKeyFile,
		StateDBFile:         filepath.Clean(stateDBFile),
		LogLevel:            "info",
		AllowPrivateTargets: allowPrivateTargets,
		MaxConnections:      256,
		MaxTCPStreams:       256,
		MaxTotalTCPStreams:  4096,
		MaxUDPRoutes:        128,
		MaxTotalUDPRoutes:   1024,
		UDPIdleSeconds:      120,
		HandshakeSeconds:    10,
		TargetDialSeconds:   10,
		PolicyVersion:       1,
		Users:               users,
		LocalControl: &LocalControlConfig{
			PeerUID:    peerUID,
			SocketPath: socketPath,
		},
	}
	if settings.IdentityTLS != nil {
		config.IdentityTLS = &ManagementIdentityTLS{
			ServerName:    settings.IdentityTLS.ServerName,
			TargetAddress: settings.IdentityTLS.TargetAddress,
			ClientID:      settings.IdentityTLS.ClientID,
			Secret:        settings.IdentityTLS.Secret,
			PrivateKey:    settings.IdentityTLS.PrivateKey,
			ShortID:       settings.IdentityTLS.ShortID,
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return DesiredState{}, err
	}
	digest := sha256.Sum256(encoded)
	userRevision, err := RuntimeUsersRevision(users)
	if err != nil {
		return DesiredState{}, err
	}
	shouldRun := inbound.Enable && enabledUsers > 0
	reason := "ready"
	if !inbound.Enable {
		reason = "inbound_disabled"
	} else if enabledUsers == 0 {
		reason = "waiting_for_enabled_users"
	}
	return DesiredState{
		InboundID:    inbound.Id,
		Revision:     hex.EncodeToString(digest[:]),
		UserRevision: userRevision,
		ServerName:   identityServerName(settings),
		ShouldRun:    shouldRun,
		Reason:       reason,
		UserCount:    len(settings.Clients),
		EnabledUsers: enabledUsers,
		Config:       config,
	}, nil
}

// UserRevisionForInbound computes the runtime user-policy revision without
// requiring supervisor-owned state paths.
func UserRevisionForInbound(inbound *model.Inbound) (string, error) {
	return UserRevisionForInboundWithPolicies(inbound, nil)
}

func UserRevisionForInboundWithPolicies(inbound *model.Inbound, policies map[string]RuntimePolicy) (string, error) {
	settings, err := ParseSettings(inboundSettings(inbound))
	if err != nil {
		return "", err
	}
	users := make(map[string]desiredUser, len(settings.Clients))
	for _, client := range settings.Clients {
		policy := RuntimePolicy{Enabled: client.Enable, ExpiresAtUnixMilli: client.ExpiryTime}
		if policies != nil {
			var ok bool
			policy, ok = policies[client.ID]
			if !ok {
				return "", fmt.Errorf("runtime policy is missing for GhostLink client %q", client.ID)
			}
		}
		users[client.ID] = desiredUser{
			Secret:             client.Secret,
			Enabled:            policy.Enabled,
			MaxTrafficBytes:    policy.MaxTrafficBytes,
			ExpiresAtUnixMilli: policy.ExpiresAtUnixMilli,
			PolicyVersion:      1,
			MaxConnections:     -1,
			MaxTCPStreams:      -1,
			MaxUDPRoutes:       -1,
		}
	}
	if policies != nil && len(policies) != len(settings.Clients) {
		return "", errors.New("runtime policy set does not match the GhostLink client set")
	}
	return RuntimeUsersRevision(users)
}

func EnabledUsersForInbound(inbound *model.Inbound) (int, error) {
	settings, err := ParseSettings(inboundSettings(inbound))
	if err != nil {
		return 0, err
	}
	enabled := 0
	for _, client := range settings.Clients {
		if client.Enable {
			enabled++
		}
	}
	return enabled, nil
}

func inboundSettings(inbound *model.Inbound) string {
	if inbound == nil {
		return ""
	}
	return inbound.Settings
}

func canonicalWebBackendURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func identityServerName(settings Settings) string {
	if settings.IdentityTLS != nil {
		return settings.IdentityTLS.ServerName
	}
	return settings.ServerName
}

// ProtectedJSON returns the secret-bearing config. Callers must write it only
// to a protected local file or authenticated local control channel.
func (s DesiredState) ProtectedJSON() ([]byte, error) {
	return json.MarshalIndent(s.Config, "", "  ")
}

// RedactedJSON is safe for logs, status APIs, and test diagnostics.
func (s DesiredState) RedactedJSON() ([]byte, error) {
	return json.Marshal(RedactedSummary{
		InboundID:    s.InboundID,
		Revision:     s.Revision,
		UserRevision: s.UserRevision,
		ServerName:   s.ServerName,
		Listen:       s.Config.Listen,
		ShouldRun:    s.ShouldRun,
		Reason:       s.Reason,
		UserCount:    s.UserCount,
		EnabledUsers: s.EnabledUsers,
	})
}

func (s DesiredState) String() string {
	return fmt.Sprintf("GhostLink state inbound=%d revision=%s should_run=%t reason=%s users=%d enabled=%d",
		s.InboundID, s.Revision, s.ShouldRun, s.Reason, s.UserCount, s.EnabledUsers)
}
