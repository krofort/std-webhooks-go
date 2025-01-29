package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// HMACSignerAndVerifier implements both Signer and Verifier interfaces using HMAC-SHA256
type HMACSignerAndVerifier struct {
	key []byte
}

// NewHMACSignerAndVerifier creates a new HMAC signer/verifier from a secret key
func NewHMACSignerAndVerifier(key []byte) *HMACSignerAndVerifier {
	return &HMACSignerAndVerifier{
		key: key,
	}
}

// Version returns the version string for HMAC signer
func (s *HMACSignerAndVerifier) Version() string {
	return "v1"
}

// Sign signs the message using HMAC-SHA256
func (s *HMACSignerAndVerifier) Sign(message []byte) ([]byte, error) {
	if len(s.key) == 0 {
		return nil, errors.New("key required for signing")
	}

	mac := hmac.New(sha256.New, s.key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

// Verify verifies the message using HMAC-SHA256
func (s *HMACSignerAndVerifier) Verify(message, signature []byte) error {
	if len(s.key) == 0 {
		return errors.New("key required for verification")
	}

	expectedMAC := hmac.New(sha256.New, s.key)
	expectedMAC.Write(message)

	if !hmac.Equal(signature, expectedMAC.Sum(nil)) {
		return ErrNoMatchingSignature
	}

	return nil
}
