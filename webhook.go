package webhooks

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderWebhookID        string = "webhook-id"
	HeaderWebhookSignature string = "webhook-signature"
	HeaderWebhookTimestamp string = "webhook-timestamp"
)

var base64enc = base64.StdEncoding

var tolerance = 5 * time.Minute

var (
	ErrRequiredHeaders     = errors.New("missing required headers")
	ErrInvalidHeaders      = errors.New("invalid signature headers")
	ErrNoMatchingSignature = errors.New("no matching signature found")
	ErrMessageTooOld       = errors.New("message timestamp too old")
	ErrMessageTooNew       = errors.New("message timestamp too new")
	ErrInvalidKeyType      = errors.New("invalid key type")
	ErrNoSigners           = errors.New("no signers configured")
	ErrNoVerifiers         = errors.New("no verifiers configured")
)

// Signer represents a webhook signing implementation
type Signer interface {
	// Version returns the version string for this signer (e.g. "v1" or "v1a")
	Version() string
	// Sign signs the given message and returns the signature
	Sign(message []byte) ([]byte, error)
}

// Verifier represents a webhook verification implementation
type Verifier interface {
	// Version returns the version string for this verifier (e.g. "v1" or "v1a")
	Version() string
	// Verify verifies the given message with the signature
	Verify(message, signature []byte) error
}

// WebhookSigner handles webhook signing
type WebhookSigner struct {
	signers []Signer
}

// WebhookVerifier handles webhook verification
type WebhookVerifier struct {
	verifiers []Verifier
}

// NewWebhookSigner creates a new webhook signer with multiple signers
func NewWebhookSigner(signers ...Signer) *WebhookSigner {
	return &WebhookSigner{
		signers: signers,
	}
}

// NewWebhookVerifier creates a new webhook verifier with multiple verifiers
func NewWebhookVerifier(verifiers ...Verifier) *WebhookVerifier {
	return &WebhookVerifier{
		verifiers: verifiers,
	}
}

// AddSigner adds a new signer to the webhook signer
func (wh *WebhookSigner) AddSigner(s Signer) {
	wh.signers = append(wh.signers, s)
}

// AddVerifier adds a new verifier to the webhook verifier
func (wh *WebhookVerifier) AddVerifier(v Verifier) {
	wh.verifiers = append(wh.verifiers, v)
}

// Verify verifies the webhook payload and headers
func (wh *WebhookVerifier) Verify(payload []byte, headers http.Header) error {
	if len(wh.verifiers) == 0 {
		return ErrNoVerifiers
	}
	return wh.verify(payload, headers, true)
}

func (wh *WebhookVerifier) verify(payload []byte, headers http.Header, enforceTolerance bool) error {
	msgID := headers.Get(HeaderWebhookID)
	msgSignature := headers.Get(HeaderWebhookSignature)
	msgTimestamp := headers.Get(HeaderWebhookTimestamp)
	if msgID == "" || msgSignature == "" || msgTimestamp == "" {
		return fmt.Errorf("unable to verify payload, err: %w", ErrRequiredHeaders)
	}

	timestamp, err := parseTimestampHeader(msgTimestamp)
	if err != nil {
		return fmt.Errorf("unable to verify payload, err: %w", err)
	}

	if enforceTolerance {
		if err := verifyTimestamp(timestamp); err != nil {
			return fmt.Errorf("unable to verify payload, err: %w", err)
		}
	}

	toSign := fmt.Sprintf("%s.%d.%s", msgID, timestamp.Unix(), payload)
	passedSignatures := strings.Split(msgSignature, " ")

	for _, versionedSignature := range passedSignatures {
		sigParts := strings.Split(versionedSignature, ",")
		if len(sigParts) < 2 {
			continue
		}

		version := sigParts[0]
		decodedSignature, err := base64enc.DecodeString(sigParts[1])
		if err != nil {
			continue
		}

		// Try each verifier that matches the version
		for _, verifier := range wh.verifiers {
			if verifier.Version() != version {
				continue
			}

			err := verifier.Verify([]byte(toSign), decodedSignature)
			if err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("unable to verify payload, err: %w", ErrNoMatchingSignature)
}

// Sign signs the webhook payload with all configured signers
func (wh *WebhookSigner) Sign(msgID string, timestamp time.Time, payload []byte) (string, error) {
	if len(wh.signers) == 0 {
		return "", ErrNoSigners
	}

	toSign := fmt.Sprintf("%s.%d.%s", msgID, timestamp.Unix(), payload)
	var signatures []string

	for _, signer := range wh.signers {
		signature, err := signer.Sign([]byte(toSign))
		if err != nil {
			continue
		}

		sig := make([]byte, base64enc.EncodedLen(len(signature)))
		base64enc.Encode(sig, signature)
		signatures = append(signatures, fmt.Sprintf("%s,%s", signer.Version(), sig))
	}

	if len(signatures) == 0 {
		return "", fmt.Errorf("unable to sign payload, err: %w", ErrNoSigners)
	}

	return strings.Join(signatures, " "), nil
}

func parseTimestampHeader(timestampHeader string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to parse timestamp header, err: %w", errors.Join(err, ErrInvalidHeaders))
	}
	timestamp := time.Unix(timeInt, 0)
	return timestamp, nil
}

func verifyTimestamp(timestamp time.Time) error {
	now := time.Now()

	if now.Sub(timestamp) > tolerance {
		return ErrMessageTooOld
	}

	if timestamp.After(now.Add(tolerance)) {
		return ErrMessageTooNew
	}

	return nil
}
