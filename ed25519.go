package webhooks

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ED25519Signer implements the Signer interface using ED25519
type ED25519Signer struct {
	privateKey ed25519.PrivateKey
}

// ED25519Verifier implements the Verifier interface using ED25519
type ED25519Verifier struct {
	publicKey ed25519.PublicKey
}

// NewED25519Signer creates a new ED25519 signer from a private key
func NewED25519Signer(key ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{
		privateKey: key,
	}
}

// NewED25519Verifier creates a new ED25519 verifier from a public key
func NewED25519Verifier(key ed25519.PublicKey) *ED25519Verifier {
	return &ED25519Verifier{
		publicKey: key,
	}
}

// Version returns the version string for ED25519 signer
func (s *ED25519Signer) Version() string {
	return "v1a"
}

// Sign signs the message using ED25519
func (s *ED25519Signer) Sign(message []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("private key required for signing")
	}

	var err error
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unable to sign payload, err: %w", errors.Join(r.(error), ErrInvalidHeaders))
		}
	}()

	signature := ed25519.Sign(s.privateKey, message)
	return signature, err
}

// Version returns the version string for ED25519 verifier
func (s *ED25519Verifier) Version() string {
	return "v1a"
}

// Verify verifies the message using ED25519
func (s *ED25519Verifier) Verify(message, signature []byte) error {
	if s.publicKey == nil {
		return errors.New("public key required for verification")
	}

	if !ed25519.Verify(s.publicKey, message, signature) {
		return ErrNoMatchingSignature
	}

	return nil
}
