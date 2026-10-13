package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"whoami/internal/store"
)

// keyring derives every stored identifier with HMAC-SHA256 under a secret
// that is generated on first start and never leaves the data directory. The
// store therefore holds no value that can be matched against a fingerprint
// computed elsewhere, and nothing in it can be reversed into attributes.
type keyring struct{ secret []byte }

func loadKeyring(path string) (*keyring, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
		return &keyring{secret: b}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("%s: secret too short", path)
	}
	return &keyring{secret: b}, nil
}

func (k *keyring) mac(label string, parts ...string) [32]byte {
	h := hmac.New(sha256.New, k.secret)
	h.Write([]byte(label))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// id returns a 128-bit identifier for the given domain and input.
func (k *keyring) id(label string, parts ...string) store.ID {
	sum := k.mac(label, parts...)
	return store.ID(sum[:16])
}

// short returns a 64-bit keyed hash, used for attribute values and cookies.
func (k *keyring) short(label string, parts ...string) uint64 {
	sum := k.mac(label, parts...)
	return binary.BigEndian.Uint64(sum[:8])
}
