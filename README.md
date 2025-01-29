# Standard Webhooks Implementation in Go

A Go implementation of the [Standard Webhooks specification](https://www.standardwebhooks.com/). This package provides a secure, reliable, and standard way to sign and verify webhook payloads, making it easier for providers to send and consumers to receive webhooks.

## Features

- Full compliance with the Standard Webhooks specification
- Multiple signature algorithms support:
  - ED25519 (asymmetric, `v1a`)
  - HMAC-SHA256 (symmetric, `v1`)
- Multiple simultaneous signers and verifiers for graceful algorithm transitions
- Protection against replay attacks with timestamp validation
- Extensible interface for custom signing methods
- Thread-safe implementation
- Comprehensive test coverage

## Installation

```bash
go get github.com/krofort/std-webhooks-go
```

## Quick Start

### Basic Usage with HMAC (Recommended for Getting Started)

```go
import "github.com/krofort/std-webhooks-go"

// Create a signer and verifier with HMAC
key := []byte("your-secret-key")
signer := webhooks.NewWebhookSigner(webhooks.NewHMACSigner(key))
verifier := webhooks.NewWebhookVerifier(webhooks.NewHMACSigner(key))

// Sign a payload
signature, err := signer.Sign("message-id", time.Now(), []byte("your-payload"))
if err != nil {
    log.Fatal(err)
}

// Verify a payload
headers := http.Header{}
headers.Set(webhooks.HeaderWebhookID, "message-id")
headers.Set(webhooks.HeaderWebhookSignature, signature)
headers.Set(webhooks.HeaderWebhookTimestamp, strconv.FormatInt(time.Now().Unix(), 10))

err = verifier.Verify([]byte("your-payload"), headers)
if err != nil {
    log.Fatal(err)
}
```

### Using ED25519 (Recommended for Production)

```go
// Generate or load your ED25519 keys
publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

// Create signer and verifier
signer := webhooks.NewWebhookSigner(webhooks.NewED25519Signer(privateKey))
verifier := webhooks.NewWebhookVerifier(webhooks.NewED25519Verifier(publicKey))
```

### Multiple Signature Methods (For Algorithm Transitions)

```go
// Create signers with both ED25519 and HMAC
signer := webhooks.NewWebhookSigner(
    webhooks.NewED25519Signer(privateKey),
    webhooks.NewHMACSigner(hmacKey),
)

// Create verifier with both ED25519 and HMAC
verifier := webhooks.NewWebhookVerifier(
    webhooks.NewED25519Verifier(publicKey),
    webhooks.NewHMACSigner(hmacKey),
)

// Or add them dynamically
signer.AddSigner(webhooks.NewHMACSigner(anotherKey))
verifier.AddVerifier(webhooks.NewHMACSigner(anotherKey))
```

## Standard Webhooks Compliance

This implementation follows the Standard Webhooks specification for:

### HTTP Headers

The package uses the standard webhook headers:
- `webhook-id`: A unique identifier for the webhook message
- `webhook-signature`: The signature(s) of the payload
- `webhook-timestamp`: Unix timestamp of when the webhook was sent

### Signature Format

The signature format follows the standard:
```
<version>,<base64-signature>
```

When using multiple signers, signatures are space-separated:
```
v1a,<base64-ed25519-sig> v1,<base64-hmac-sig>
```

### Security Features

- **Replay Attack Prevention**: Includes timestamp validation with a 5-minute tolerance
- **Multiple Signatures**: Supports multiple signing algorithms for security and flexibility
- **Standard Cryptography**: Uses well-tested Go crypto packages
- **Non-repudiation**: Supports ED25519 for cryptographic proof of origin
- **HMAC Support**: Provides symmetric key verification option

## Implementing Custom Signers

You can implement custom signing methods by implementing the `Signer` and/or `Verifier` interfaces:

```go
type Signer interface {
    Version() string
    Sign(message []byte) ([]byte, error)
}

type Verifier interface {
    Version() string
    Verify(message, signature []byte) error
}
```

## Error Handling

The package provides standard error types:
- `ErrRequiredHeaders`: Missing required headers
- `ErrInvalidHeaders`: Invalid header format
- `ErrNoMatchingSignature`: No valid signature found
- `ErrMessageTooOld`: Message timestamp is too old
- `ErrMessageTooNew`: Message timestamp is in the future
- `ErrNoSigners`: No signers configured
- `ErrNoVerifiers`: No verifiers configured

## Best Practices

1. **Algorithm Choice**:
   - Use ED25519 for production environments where non-repudiation is important
   - Use HMAC for simpler implementations or when sharing public keys is impractical

2. **Key Management**:
   - Rotate keys periodically
   - Use environment variables or secure key management systems
   - Never hardcode secret keys

3. **Signature Verification**:
   - Always verify timestamps to prevent replay attacks
   - Implement proper error handling for all verification steps
   - Consider using multiple signature methods during algorithm transitions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Make sure to read the [Standard Webhooks Specification](https://www.standardwebhooks.com/) before contributing.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Resources

- [Standard Webhooks Specification](https://www.standardwebhooks.com/)
- [Standard Webhooks GitHub](https://github.com/standard-webhooks/standard-webhooks)

