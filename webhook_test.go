package webhooks

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSingleED25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating ED25519 key: %s", err)
	}

	signer := NewWebhookSigner(NewED25519Signer(priv))
	verifier := NewWebhookVerifier(NewED25519Verifier(pub))

	now := time.Now()

	sig, err := signer.Sign("msg-id", now, []byte("payload"))
	if err != nil {
		t.Errorf("Error signing message: %s", err)
	}

	headers := http.Header{}
	headers.Set(HeaderWebhookID, "msg-id")
	headers.Set(HeaderWebhookSignature, sig)
	headers.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = verifier.Verify([]byte("payload"), headers)
	if err != nil {
		t.Errorf("Error verifying message: %s", err)
	}
}

func TestSingleHMAC(t *testing.T) {
	key := []byte("test-secret-key")
	signer := NewWebhookSigner(NewHMACSignerAndVerifier(key))
	verifier := NewWebhookVerifier(NewHMACSignerAndVerifier(key))

	now := time.Now()

	sig, err := signer.Sign("msg-id", now, []byte("payload"))
	if err != nil {
		t.Errorf("Error signing message: %s", err)
	}

	headers := http.Header{}
	headers.Set(HeaderWebhookID, "msg-id")
	headers.Set(HeaderWebhookSignature, sig)
	headers.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = verifier.Verify([]byte("payload"), headers)
	if err != nil {
		t.Errorf("Error verifying message: %s", err)
	}
}

func TestMultipleSignersAndVerifiers(t *testing.T) {
	// Generate ED25519 keys
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating ED25519 key: %s", err)
	}

	// Create HMAC keys
	hmacKey := []byte("test-secret-key")

	// Create signers with both ED25519 and HMAC
	signer := NewWebhookSigner(
		NewED25519Signer(priv),
		NewHMACSignerAndVerifier(hmacKey),
	)

	// Create verifier with both ED25519 and HMAC
	verifier := NewWebhookVerifier(
		NewED25519Verifier(pub),
		NewHMACSignerAndVerifier(hmacKey),
	)

	now := time.Now()

	// Sign with both methods
	sig, err := signer.Sign("msg-id", now, []byte("payload"))
	if err != nil {
		t.Errorf("Error signing message: %s", err)
	}

	// Verify that both signatures are present
	signatures := strings.Split(sig, " ")
	if len(signatures) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(signatures))
	}

	var hasED25519, hasHMAC bool
	for _, s := range signatures {
		if strings.HasPrefix(s, "v1a,") {
			hasED25519 = true
		}
		if strings.HasPrefix(s, "v1,") {
			hasHMAC = true
		}
	}

	if !hasED25519 {
		t.Error("Missing ED25519 signature")
	}
	if !hasHMAC {
		t.Error("Missing HMAC signature")
	}

	// Verify with both methods
	headers := http.Header{}
	headers.Set(HeaderWebhookID, "msg-id")
	headers.Set(HeaderWebhookSignature, sig)
	headers.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = verifier.Verify([]byte("payload"), headers)
	if err != nil {
		t.Errorf("Error verifying message: %s", err)
	}

	// Test adding signers/verifiers dynamically
	signer2 := NewWebhookSigner()
	signer2.AddSigner(NewED25519Signer(priv))
	signer2.AddSigner(NewHMACSignerAndVerifier(hmacKey))

	verifier2 := NewWebhookVerifier()
	verifier2.AddVerifier(NewED25519Verifier(pub))
	verifier2.AddVerifier(NewHMACSignerAndVerifier(hmacKey))

	sig2, err := signer2.Sign("msg-id", now, []byte("payload"))
	if err != nil {
		t.Errorf("Error signing message with dynamic signers: %s", err)
	}

	headers2 := http.Header{}
	headers2.Set(HeaderWebhookID, "msg-id")
	headers2.Set(HeaderWebhookSignature, sig2)
	headers2.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = verifier2.Verify([]byte("payload"), headers2)
	if err != nil {
		t.Errorf("Error verifying message with dynamic verifiers: %s", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	// Test with ED25519
	pubED, _, _ := ed25519.GenerateKey(rand.Reader)
	_, privED2, _ := ed25519.GenerateKey(rand.Reader)

	signer := NewWebhookSigner(NewED25519Signer(privED2))
	verifier := NewWebhookVerifier(NewED25519Verifier(pubED))

	now := time.Now()

	sig, err := signer.Sign("msg-id", now, []byte("payload"))
	if err != nil {
		t.Errorf("Error signing message: %s", err)
	}

	headers := http.Header{}
	headers.Set(HeaderWebhookID, "msg-id")
	headers.Set(HeaderWebhookSignature, sig)
	headers.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = verifier.Verify([]byte("payload"), headers)
	if err == nil {
		t.Error("Expected error verifying message with wrong ED25519 key")
	}

	// Test with HMAC
	key1 := []byte("secret-key-1")
	key2 := []byte("secret-key-2")

	hmacSigner := NewWebhookSigner(NewHMACSignerAndVerifier(key1))
	hmacVerifier := NewWebhookVerifier(NewHMACSignerAndVerifier(key2))

	sigHMAC, err := hmacSigner.Sign("msg-id", now, []byte("payload"))
	if err != nil {
		t.Errorf("Error signing message: %s", err)
	}

	headersHMAC := http.Header{}
	headersHMAC.Set(HeaderWebhookID, "msg-id")
	headersHMAC.Set(HeaderWebhookSignature, sigHMAC)
	headersHMAC.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = hmacVerifier.Verify([]byte("payload"), headersHMAC)
	if err == nil {
		t.Error("Expected error verifying message with wrong HMAC key")
	}
}

func TestNoSignersOrVerifiers(t *testing.T) {
	emptySigner := NewWebhookSigner()
	emptyVerifier := NewWebhookVerifier()

	now := time.Now()

	_, err := emptySigner.Sign("msg-id", now, []byte("payload"))
	if err != ErrNoSigners {
		t.Error("Expected ErrNoSigners when signing with no signers")
	}

	headers := http.Header{}
	headers.Set(HeaderWebhookID, "msg-id")
	headers.Set(HeaderWebhookSignature, "v1,abc")
	headers.Set(HeaderWebhookTimestamp, strconv.FormatInt(now.Unix(), 10))

	err = emptyVerifier.Verify([]byte("payload"), headers)
	if err != ErrNoVerifiers {
		t.Error("Expected ErrNoVerifiers when verifying with no verifiers")
	}
}
