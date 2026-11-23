package connection

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// KEK wraps and unwraps per-connection DEKs (threat model T3). The
// production implementation is TransitKEK: the key never leaves Vault and
// only the service role can call unwrap. LocalKEK exists for preview and
// tests and refuses to be built anywhere else.
type KEK interface {
	// ID names the key. It is stored with every wrapped DEK, and Unwrap of
	// a DEK wrapped under another ID is refused rather than attempted.
	ID() string
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// KEK modes accepted by NewKEK. There is no default.
const (
	KEKModeTransit = "transit"
	KEKModeLocal   = "local"
)

// ErrKEKConfig is returned for every KEK configuration NewKEK refuses.
var ErrKEKConfig = errors.New("pa connection: kek configuration refused")

// KEKConfig selects and configures the KEK. Every field must be set
// explicitly; an empty or unknown Mode is refused, never defaulted.
type KEKConfig struct {
	// Mode is KEKModeTransit or KEKModeLocal (PA_KEK_MODE).
	Mode string
	// Environment is the deployment tier (ENV). KEKModeLocal is accepted only
	// when it names preview or a local/test tier; an empty or unknown value
	// is treated as production.
	Environment string
	// LocalKey is the 32-byte local KEK (PA_KEK_LOCAL_KEY, base64).
	LocalKey []byte
	// Transit configures the Vault transit key.
	Transit TransitConfig
}

// LoadKEKConfig reads a KEKConfig from the environment through getenv. It
// does not validate; NewKEK does. Not wired into startup yet: the linking
// slice of #1314 does that, behind PA_ENABLED.
func LoadKEKConfig(getenv func(string) string) (KEKConfig, error) {
	c := KEKConfig{
		Mode:        strings.TrimSpace(getenv("PA_KEK_MODE")),
		Environment: strings.TrimSpace(getenv("ENV")),
		Transit: TransitConfig{
			Address: strings.TrimSpace(getenv("PA_KEK_TRANSIT_ADDR")),
			Mount:   strings.TrimSpace(getenv("PA_KEK_TRANSIT_MOUNT")),
			KeyName: strings.TrimSpace(getenv("PA_KEK_TRANSIT_KEY")),
		},
	}
	if v := getenv("PA_KEK_LOCAL_KEY"); v != "" {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return KEKConfig{}, fmt.Errorf("%w: PA_KEK_LOCAL_KEY is not base64", ErrKEKConfig)
		}
		c.LocalKey = k
	}
	return c, nil
}

// LocalKEKTiers are the ENV values (compared case-insensitively) on which a
// local KEK is allowed: preview, plus the local and test tiers of
// config.LocalTiers, which a test keeps in step (this package cannot import
// config: config's tests import internal/db, which imports this package).
// The production deployment leaves ENV unset, so empty is not among them.
var LocalKEKTiers = []string{"preview", "local", "local-dev", "localdev", "dev", "development", "test", "ci"}

func localKEKAllowed(env string) bool {
	env = strings.TrimSpace(env)
	for _, t := range LocalKEKTiers {
		if strings.EqualFold(env, t) {
			return true
		}
	}
	return false
}

// NewKEK builds the configured KEK, failing closed: an empty or unknown mode,
// a local KEK outside preview and the local tiers, and an incomplete transit
// configuration are all refused. This is the production startup check of
// threat model T3 ("a production deployment with a KV KEK fails").
func NewKEK(c KEKConfig) (KEK, error) {
	// Each constructor's result is checked before it becomes a KEK: a nil
	// *TransitKEK returned as a KEK would be a non-nil interface.
	switch c.Mode {
	case KEKModeTransit:
		k, err := NewTransitKEK(c.Transit)
		if err != nil {
			return nil, err
		}
		return k, nil
	case KEKModeLocal:
		k, err := NewLocalKEK(c.LocalKey, c.Environment)
		if err != nil {
			return nil, err
		}
		return k, nil
	case "":
		return nil, fmt.Errorf("%w: PA_KEK_MODE is not set", ErrKEKConfig)
	default:
		return nil, fmt.Errorf("%w: unknown PA_KEK_MODE", ErrKEKConfig)
	}
}

// LocalKEK is an AES-256-GCM KEK held in process memory (a Vault KV value or
// a test key). It is refused in production: with it, an operator who can
// read the database and the pod environment reads every token.
type LocalKEK struct {
	id  string
	gcm cipher.AEAD
}

// NewLocalKEK builds a LocalKEK, refusing unless env names preview or a local
// or test tier.
func NewLocalKEK(key []byte, env string) (*LocalKEK, error) {
	if !localKEKAllowed(env) {
		return nil, fmt.Errorf("%w: a local KEK is allowed only on preview or a local tier", ErrKEKConfig)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: local KEK must be 32 bytes", ErrKEKConfig)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKEKConfig, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKEKConfig, err)
	}
	sum := sha256.Sum256(append([]byte("pa-kek-id|"), key...))
	return &LocalKEK{id: "local:" + hex.EncodeToString(sum[:8]), gcm: gcm}, nil
}

func (k *LocalKEK) ID() string { return k.id }

func (k *LocalKEK) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	nonce := make([]byte, k.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("pa connection: kek nonce: %w", err)
	}
	return k.gcm.Seal(nonce, nonce, dek, []byte(k.id)), nil
}

func (k *LocalKEK) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	n := k.gcm.NonceSize()
	if len(wrapped) < n+k.gcm.Overhead() {
		return nil, fmt.Errorf("%w: wrapped dek too short", ErrUnreadable)
	}
	dek, err := k.gcm.Open(nil, wrapped[:n], wrapped[n:], []byte(k.id))
	if err != nil {
		return nil, fmt.Errorf("%w: wrapped dek does not open", ErrUnreadable)
	}
	return dek, nil
}

// TokenSource returns a Vault token for the service role (for example from
// Kubernetes auth). It is called per request so a renewed token is used.
type TokenSource func(ctx context.Context) (string, error)

// TransitConfig configures TransitKEK.
type TransitConfig struct {
	// Address is the Vault base URL. https only.
	Address string
	// Mount is the transit secrets engine mount path, e.g. "transit".
	Mount string
	// KeyName is the transit key, which must be non-exportable.
	KeyName string
	// Token supplies the Vault token. Required.
	Token TokenSource
	// HTTPClient is used for every call. Required: Vault is an in-cluster
	// service, not a catalog server, so the T9 egress client (which refuses
	// private addresses) does not fit it, and this package builds no client
	// of its own (internal/pa egress guard). The caller supplies one with
	// the Vault CA, no proxy, no redirects and a timeout.
	HTTPClient *http.Client
}

var transitPathPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})*$`)

// TransitKEK wraps DEKs with a Vault transit key: the encrypt and decrypt
// endpoints of the transit engine. The key material never leaves Vault.
type TransitKEK struct {
	base   string
	mount  string
	key    string
	token  TokenSource
	client *http.Client
}

// maxVaultBody caps a Vault response body.
const maxVaultBody = 64 << 10

// NewTransitKEK validates c and builds a TransitKEK. It makes no call.
func NewTransitKEK(c TransitConfig) (*TransitKEK, error) {
	u, err := url.Parse(c.Address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: transit address must be an https URL", ErrKEKConfig)
	}
	if !transitPathPart.MatchString(c.Mount) || !transitPathPart.MatchString(c.KeyName) || strings.Contains(c.KeyName, "/") {
		return nil, fmt.Errorf("%w: transit mount and key name are required", ErrKEKConfig)
	}
	if c.Token == nil {
		return nil, fmt.Errorf("%w: transit token source is required", ErrKEKConfig)
	}
	if c.HTTPClient == nil {
		return nil, fmt.Errorf("%w: transit HTTP client is required", ErrKEKConfig)
	}
	client := c.HTTPClient
	return &TransitKEK{
		base:   strings.TrimRight(u.String(), "/"),
		mount:  c.Mount,
		key:    c.KeyName,
		token:  c.Token,
		client: client,
	}, nil
}

func (k *TransitKEK) ID() string { return "transit:" + k.mount + "/" + k.key }

func (k *TransitKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := k.call(ctx, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}, &out); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return nil, errors.New("pa connection: transit encrypt returned no ciphertext")
	}
	return []byte(out.Data.Ciphertext), nil
}

func (k *TransitKEK) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := k.call(ctx, "decrypt", map[string]string{"ciphertext": string(wrapped)}, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(dek) != dekSize {
		return nil, fmt.Errorf("%w: transit decrypt returned no dek", ErrUnreadable)
	}
	return dek, nil
}

func (k *TransitKEK) call(ctx context.Context, op string, body map[string]string, out any) error {
	tok, err := k.token(ctx)
	if err != nil || tok == "" {
		return errors.New("pa connection: no vault token")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pa connection: transit %s: %w", op, err)
	}
	endpoint := k.base + "/v1/" + k.mount + "/" + op + "/" + k.key
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("pa connection: transit %s: %w", op, err)
	}
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("pa connection: transit %s: request failed", op)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxVaultBody+1))
	if err != nil || len(data) > maxVaultBody {
		return fmt.Errorf("pa connection: transit %s: unreadable response", op)
	}
	if resp.StatusCode != http.StatusOK {
		// The body may echo request material; it is never included.
		return fmt.Errorf("pa connection: transit %s: status %d", op, resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("pa connection: transit %s: malformed response", op)
	}
	return nil
}
