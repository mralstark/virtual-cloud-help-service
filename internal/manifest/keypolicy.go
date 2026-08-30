package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
)

const (
	keyPolicyContext  = "virtual-cloud-help-service/manifest-key-policy/v1"
	maxKeyPolicyBytes = 32 << 10
	maxPolicyKeys     = 64
)

// KeyPolicy is signed by an offline root key and carried inside every manifest.
// Its non-overlapping grants prevent two online manifest keys from authorizing the
// same version.
type KeyPolicy struct {
	Version   uint64     `json:"version"`
	RootKeyID string     `json:"root_key_id"`
	Keys      []KeyGrant `json:"keys"`
	Signature string     `json:"signature"`
}

type KeyGrant struct {
	KeyID            string `json:"key_id"`
	PublicKey        string `json:"public_key"`
	Epoch            uint64 `json:"epoch"`
	NotBeforeVersion uint64 `json:"not_before_version"`
	// NotAfterVersion is inclusive. Zero means that the final grant is open-ended.
	NotAfterVersion uint64 `json:"not_after_version"`
}

type keyPolicyPayload struct {
	Context   string     `json:"context"`
	Version   uint64     `json:"version"`
	RootKeyID string     `json:"root_key_id"`
	Keys      []KeyGrant `json:"keys"`
}

func NewKeyGrant(publicKey ed25519.PublicKey, epoch, notBeforeVersion, notAfterVersion uint64) (KeyGrant, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return KeyGrant{}, errors.New("manifest: invalid manifest public key")
	}
	return KeyGrant{
		KeyID:            KeyID(publicKey),
		PublicKey:        base64.RawURLEncoding.EncodeToString(publicKey),
		Epoch:            epoch,
		NotBeforeVersion: notBeforeVersion,
		NotAfterVersion:  notAfterVersion,
	}, nil
}

func SignKeyPolicy(rootPrivateKey ed25519.PrivateKey, version uint64, grants []KeyGrant) (KeyPolicy, error) {
	if !validEd25519PrivateKey(rootPrivateKey) {
		return KeyPolicy{}, errors.New("manifest: invalid offline root private key")
	}
	rootPublicKey := rootPrivateKey.Public().(ed25519.PublicKey)
	policy := KeyPolicy{
		Version:   version,
		RootKeyID: KeyID(rootPublicKey),
		Keys:      canonicalKeyGrants(grants),
	}
	if err := validateKeyPolicyShape(policy); err != nil {
		return KeyPolicy{}, err
	}
	payload, err := keyPolicySigningBytes(policy)
	if err != nil {
		return KeyPolicy{}, err
	}
	policy.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPrivateKey, payload))
	return policy, nil
}

func validEd25519PrivateKey(privateKey ed25519.PrivateKey) bool {
	if len(privateKey) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return bytes.Equal(derived, privateKey)
}

// ValidateKeyPolicy verifies the offline-root signature and returns a stable digest
// used to reject same-version policy equivocation.
func ValidateKeyPolicy(policy KeyPolicy, rootPublicKey ed25519.PublicKey) (string, error) {
	if len(rootPublicKey) != ed25519.PublicKeySize {
		return "", errors.New("manifest: invalid offline root public key")
	}
	if err := validateKeyPolicyShape(policy); err != nil {
		return "", err
	}
	if policy.RootKeyID != KeyID(rootPublicKey) {
		return "", errors.New("manifest: key policy root does not match the pinned offline root")
	}
	signature, err := base64.RawURLEncoding.DecodeString(policy.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", errors.New("manifest: key policy signature is invalid")
	}
	payload, err := keyPolicySigningBytes(policy)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(rootPublicKey, payload, signature) {
		return "", errors.New("manifest: key policy signature verification failed")
	}
	canonical, err := json.Marshal(KeyPolicy{
		Version: policy.Version, RootKeyID: policy.RootKeyID,
		Keys: canonicalKeyGrants(policy.Keys), Signature: policy.Signature,
	})
	if err != nil {
		return "", fmt.Errorf("manifest: encode canonical key policy: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func KeyPolicyGrant(policy KeyPolicy, keyID string, version uint64) (KeyGrant, ed25519.PublicKey, error) {
	for _, grant := range policy.Keys {
		if grant.KeyID != keyID {
			continue
		}
		if version < grant.NotBeforeVersion || (grant.NotAfterVersion != 0 && version > grant.NotAfterVersion) {
			return KeyGrant{}, nil, fmt.Errorf("manifest: signing key %q is not authorized for version %d", keyID, version)
		}
		raw, err := base64.RawURLEncoding.DecodeString(grant.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return KeyGrant{}, nil, errors.New("manifest: key policy contains an invalid public key")
		}
		return grant, ed25519.PublicKey(raw), nil
	}
	return KeyGrant{}, nil, fmt.Errorf("manifest: signing key %q is absent from key policy", keyID)
}

func DecodeKeyPolicy(reader io.Reader) (KeyPolicy, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxKeyPolicyBytes+1))
	if err != nil {
		return KeyPolicy{}, fmt.Errorf("manifest: read key policy: %w", err)
	}
	if len(data) == 0 || len(data) > maxKeyPolicyBytes {
		return KeyPolicy{}, errors.New("manifest: key policy size is invalid")
	}
	var policy KeyPolicy
	if err := decodeStrict(data, &policy); err != nil {
		return KeyPolicy{}, fmt.Errorf("manifest: decode key policy: %w", err)
	}
	return policy, nil
}

func validateKeyPolicyShape(policy KeyPolicy) error {
	if policy.Version == 0 {
		return errors.New("manifest: key policy version must be positive")
	}
	if len(policy.RootKeyID) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return errors.New("manifest: key policy root key ID is invalid")
	}
	if len(policy.Keys) == 0 || len(policy.Keys) > maxPolicyKeys {
		return fmt.Errorf("manifest: key policy must contain between 1 and %d grants", maxPolicyKeys)
	}
	if policy.Signature != "" && len(policy.Signature) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return errors.New("manifest: encoded key policy signature size is invalid")
	}
	grants := canonicalKeyGrants(policy.Keys)
	seenKeys := make(map[string]struct{}, len(grants))
	for index, grant := range grants {
		raw, err := base64.RawURLEncoding.DecodeString(grant.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize || KeyID(ed25519.PublicKey(raw)) != grant.KeyID {
			return fmt.Errorf("manifest: key policy grant %d has an invalid key", index)
		}
		if _, exists := seenKeys[grant.KeyID]; exists {
			return fmt.Errorf("manifest: duplicate key policy grant %q", grant.KeyID)
		}
		seenKeys[grant.KeyID] = struct{}{}
		if grant.Epoch == 0 || grant.NotBeforeVersion == 0 {
			return fmt.Errorf("manifest: key policy grant %q has a zero epoch or start version", grant.KeyID)
		}
		if grant.NotAfterVersion != 0 && grant.NotAfterVersion < grant.NotBeforeVersion {
			return fmt.Errorf("manifest: key policy grant %q has an invalid version range", grant.KeyID)
		}
		if index == 0 {
			if grant.Epoch != 1 || grant.NotBeforeVersion != 1 {
				return errors.New("manifest: first key policy grant must start at epoch and version 1")
			}
			continue
		}
		previous := grants[index-1]
		if previous.NotAfterVersion == 0 || previous.NotAfterVersion == math.MaxUint64 {
			return errors.New("manifest: only the final key policy grant may be open-ended")
		}
		if grant.Epoch != previous.Epoch+1 || grant.NotBeforeVersion != previous.NotAfterVersion+1 {
			return errors.New("manifest: key policy grants must have contiguous versions and epochs")
		}
	}
	if grants[len(grants)-1].NotAfterVersion != 0 {
		return errors.New("manifest: final key policy grant must be open-ended")
	}
	return nil
}

func keyPolicySigningBytes(policy KeyPolicy) ([]byte, error) {
	payload := keyPolicyPayload{
		Context: keyPolicyContext, Version: policy.Version,
		RootKeyID: policy.RootKeyID, Keys: canonicalKeyGrants(policy.Keys),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("manifest: encode key policy signature payload: %w", err)
	}
	return encoded, nil
}

func canonicalKeyGrants(grants []KeyGrant) []KeyGrant {
	result := append([]KeyGrant(nil), grants...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].NotBeforeVersion == result[j].NotBeforeVersion {
			return result[i].KeyID < result[j].KeyID
		}
		return result[i].NotBeforeVersion < result[j].NotBeforeVersion
	})
	return result
}

func canonicalKeyPolicy(policy KeyPolicy) KeyPolicy {
	policy.Keys = canonicalKeyGrants(policy.Keys)
	return policy
}
