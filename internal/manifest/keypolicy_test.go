package manifest

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestKeyPolicyAuthorizesNonOverlappingRotation(t *testing.T) {
	rootPublicKey, rootPrivateKey := testKey(t)
	oldPublicKey, _ := testKey(t)
	newPublicKey, _ := testKey(t)
	oldGrant, err := NewKeyGrant(oldPublicKey, 1, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := NewKeyGrant(newPublicKey, 2, 11, 0)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := SignKeyPolicy(rootPrivateKey, 2, []KeyGrant{newGrant, oldGrant})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateKeyPolicy(policy, rootPublicKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := KeyPolicyGrant(policy, oldGrant.KeyID, 10); err != nil {
		t.Fatal(err)
	}
	if _, _, err := KeyPolicyGrant(policy, oldGrant.KeyID, 11); err == nil {
		t.Fatal("old key remained authorized after its final version")
	}
	if grant, _, err := KeyPolicyGrant(policy, newGrant.KeyID, 11); err != nil || grant.Epoch != 2 {
		t.Fatalf("new key grant = %+v, %v", grant, err)
	}

	tampered := policy
	tampered.Keys = append([]KeyGrant(nil), policy.Keys...)
	tampered.Keys[1].NotBeforeVersion++
	if _, err := ValidateKeyPolicy(tampered, rootPublicKey); err == nil {
		t.Fatal("ValidateKeyPolicy() accepted tampered grants")
	}
}

func TestVerifyAcceptsRootAuthorizedRotationAndRevokesOldKey(t *testing.T) {
	rootPublicKey, rootPrivateKey := testKey(t)
	oldPublicKey, oldPrivateKey := testKey(t)
	newPublicKey, newPrivateKey := testKey(t)
	oldGrant, _ := NewKeyGrant(oldPublicKey, 1, 1, 10)
	newGrant, _ := NewKeyGrant(newPublicKey, 2, 11, 0)
	policy, err := SignKeyPolicy(rootPrivateKey, 2, []KeyGrant{oldGrant, newGrant})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	oldEnvelope, err := Issue(testCatalog(), 10, policy, rootPublicKey, now, 15*time.Minute, oldPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, trusted, err := Verify(oldEnvelope, rootPublicKey, now.Add(time.Minute), TrustedState{})
	if err != nil {
		t.Fatal(err)
	}
	newEnvelope, err := Issue(testCatalog(), 11, policy, rootPublicKey, now.Add(2*time.Minute), 15*time.Minute, newPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, rotated, err := Verify(newEnvelope, rootPublicKey, now.Add(3*time.Minute), trusted)
	if err != nil {
		t.Fatalf("Verify() rejected authorized key rotation: %v", err)
	}
	if rotated.SigningKeyID != KeyID(newPublicKey) || rotated.SigningKeyEpoch != 2 {
		t.Fatalf("rotated trusted state = %+v", rotated)
	}
	if _, err := Issue(testCatalog(), 11, policy, rootPublicKey, now.Add(2*time.Minute), 15*time.Minute, oldPrivateKey); err == nil {
		t.Fatal("Issue() allowed the retired key to sign after its version range")
	}
}

func TestVerifyRejectsKeyPolicyRollbackAndEquivocation(t *testing.T) {
	rootPublicKey, rootPrivateKey := testKey(t)
	oldPublicKey, oldPrivateKey := testKey(t)
	newPublicKey, newPrivateKey := testKey(t)
	oldGrant, _ := NewKeyGrant(oldPublicKey, 1, 1, 10)
	newGrant, _ := NewKeyGrant(newPublicKey, 2, 11, 0)
	currentPolicy, _ := SignKeyPolicy(rootPrivateKey, 2, []KeyGrant{oldGrant, newGrant})
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	current, _ := Issue(testCatalog(), 11, currentPolicy, rootPublicKey, now, 15*time.Minute, newPrivateKey)
	_, trusted, err := Verify(current, rootPublicKey, now.Add(time.Minute), TrustedState{})
	if err != nil {
		t.Fatal(err)
	}

	legacyGrant, _ := NewKeyGrant(oldPublicKey, 1, 1, 0)
	legacyPolicy, _ := SignKeyPolicy(rootPrivateKey, 1, []KeyGrant{legacyGrant})
	rollback, _ := Issue(testCatalog(), 12, legacyPolicy, rootPublicKey, now.Add(2*time.Minute), 15*time.Minute, oldPrivateKey)
	if _, _, err := Verify(rollback, rootPublicKey, now.Add(3*time.Minute), trusted); err == nil {
		t.Fatal("Verify() accepted an offline-root policy rollback")
	}

	shortOld, _ := NewKeyGrant(oldPublicKey, 1, 1, 9)
	earlyNew, _ := NewKeyGrant(newPublicKey, 2, 10, 0)
	equivocatingPolicy, _ := SignKeyPolicy(rootPrivateKey, 2, []KeyGrant{shortOld, earlyNew})
	equivocation, _ := Issue(testCatalog(), 12, equivocatingPolicy, rootPublicKey, now.Add(2*time.Minute), 15*time.Minute, newPrivateKey)
	if _, _, err := Verify(equivocation, rootPublicKey, now.Add(3*time.Minute), trusted); err == nil {
		t.Fatal("Verify() accepted different root policies at the same policy version")
	}
}

func TestDecodeKeyPolicyBoundsAndUnknownFields(t *testing.T) {
	if _, err := DecodeKeyPolicy(strings.NewReader(strings.Repeat("x", maxKeyPolicyBytes+1))); err == nil {
		t.Fatal("DecodeKeyPolicy() accepted an oversized file")
	}
	unknown := `{"version":1,"root_key_id":"root","keys":[],"signature":"` +
		base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `","unknown":true}`
	if _, err := DecodeKeyPolicy(strings.NewReader(unknown)); err == nil {
		t.Fatal("DecodeKeyPolicy() accepted an unknown field")
	}
}
