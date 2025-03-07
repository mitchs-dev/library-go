// packageName: jwt

/*
Package jwt provides functions for generating and validating JSON Web Tokens (JWTs).

It supports HS256, RS256, and ES256 algorithms.

Usage:

1. Initialize the package using InitializeJWT, providing key management options.
2. Generate JWTs using GenerateToken.
3. Validate JWTs using ValidateToken.

Example:

// Initialization
keys, pubKeys, err := jwt.InitializeJWT(true, []jwt.JWTAlgorithm{jwt.HS256, jwt.RS256, jwt.ES256}, nil, nil)

	if err != nil {
	    // Handle error
	}

// Token Generation
token, exp, err := jwt.GenerateToken(jwt.HS256, "UTC", "1h", "issuer", "subject", "audience", "data")

	if err != nil {
	    // Handle error
	}

// Token Validation
valid, err := jwt.ValidateToken(token, "issuer", "audience", "UTC")

	if err != nil {
	    // Handle error
	}
*/
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/mitchs-dev/library-go/generator"
	"github.com/mitchs-dev/library-go/streaming"
	log "github.com/sirupsen/logrus"
)

// JWTAlgorithm is the algorithm used for JWT token generation
type JWTAlgorithm string

const (
	// HS256 is the HMAC SHA-256 algorithm, using a shared secret.
	HS256 = JWTAlgorithm("HS256")
	// RS256 is the RSA Signature with SHA-256 algorithm, using a public/private key pair.
	RS256 = JWTAlgorithm("RS256")
	// ES256 is the ECDSA Signature with P-256 and SHA-256 algorithm, using a public/private key pair.
	ES256 = JWTAlgorithm("ES256")
)

// AlgoKeysStruct maps JWT algorithms to their respective private keys (base64 encoded).
type AlgoKeysStruct map[JWTAlgorithm]string

// PubKeysStruct maps JWT algorithms to their respective public keys (base64 encoded).
type PubKeysStruct map[JWTAlgorithm]string

var (
	keys           AlgoKeysStruct
	publicKeys     PubKeysStruct
	jwtInitialized bool
)

// InitializeJWT initializes the JWT package with keys for generating and validating tokens.
// If generateKeys is true, new keys are generated for the specified algorithms.
// If generateKeys is false, existingKeys and existingPubKeys must be provided.
func InitializeJWT(generateKeys bool, algorithms []JWTAlgorithm, existingKeys AlgoKeysStruct, existingPubKeys PubKeysStruct) (AlgoKeysStruct, PubKeysStruct, error) {
	// Check if JWT has already been initialized
	if jwtInitialized {
		return nil, nil, errors.New("JWT has already been initialized")
	}

	// Check if generateKeys and existingKeys are set correctly
	if !generateKeys && existingKeys == nil {
		return nil, nil, errors.New("existing keys must be provided if generateKeys is false")
	} else if generateKeys && existingKeys != nil {
		return nil, nil, errors.New("existing keys must be nil if generateKeys is true")
	}

	// Generate keys if generateKeys is true
	// Otherwise, use existing keys
	if generateKeys {
		keys = make(AlgoKeysStruct)
		publicKeys = make(PubKeysStruct)
		for _, algorithm := range algorithms {
			key, pubKey, err := runGenerateKeys(algorithm)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
			}
			keys[algorithm] = key
			publicKeys[algorithm] = pubKey
		}
	} else {
		keys = existingKeys
		publicKeys = existingPubKeys
	}

	// Set JWT initialized to true
	jwtInitialized = true

	// Return the keys
	return keys, publicKeys, nil
}

func generateKey() (string, error) {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	hs256Key := base64.RawURLEncoding.EncodeToString(key)
	return hs256Key, nil
}

func generateRSAKey() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	publicKey := &privateKey.PublicKey
	privateKeyx509 := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyx509, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	rs256PrivateKey := base64.RawURLEncoding.EncodeToString(privateKeyx509)

	rs256PublicKey := base64.RawURLEncoding.EncodeToString(publicKeyx509)

	return rs256PrivateKey, rs256PublicKey, nil
}

func generateESKey() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	publicKey := &privateKey.PublicKey
	privateKeyx509, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	publicKeyx509, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	es256PrivateKey := base64.RawURLEncoding.EncodeToString(privateKeyx509)
	es256PublicKey := base64.RawURLEncoding.EncodeToString(publicKeyx509)

	return es256PrivateKey, es256PublicKey, nil
}

func runGenerateKeys(algorithm JWTAlgorithm) (string, string, error) {

	var key string
	var pubKey string
	switch algorithm {
	case HS256:
		generateH256Key, err := generateKey()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate HS256 key: %w", err)
		}
		key = generateH256Key
	case RS256:
		rs256PrivKey, rsa265PubKey, err := generateRSAKey()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate RS256 key: %w", err)
		}
		key = rs256PrivKey
		pubKey = rsa265PubKey

	case ES256:
		es256PrivKey, es256PubKey, err := generateESKey()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate ES256 key: %w", err)
		}
		key = es256PrivKey
		pubKey = es256PubKey
	}

	return key, pubKey, nil
}

// JWTToken represents a parsed or generated JWT.
type JWTToken struct {
	Header    jwtTokenHeader  `json:"header"`    // JWT header
	Payload   jwtTokenPayload `json:"payload"`   // JWT payload
	Signature string          `json:"signature"` // JWT signature (base64 encoded)
}

// jwtTokenHeader represents the JWT header.
type jwtTokenHeader struct {
	Algorithm JWTAlgorithm `json:"algorithm"` // Algorithm used for signing
	Type      string       `json:"type"`      // Token type (e.g., "JWT")
}

// jwtTokenPayload represents the JWT payload.
type jwtTokenPayload struct {
	ExpirationTime int64  `json:"expirationTime"` // Expiration time (Unix timestamp)
	IssuedAt       int64  `json:"issuedAt"`       // Issued at time (Unix timestamp)
	NotBefore      int64  `json:"notBefore"`      // Not before time (Unix timestamp)
	Issuer         string `json:"issuer"`         // Issuer of the token
	Subject        string `json:"subject"`        // Subject of the token
	Audience       string `json:"audience"`       // Audience of the token
	JwtID          string `json:"jwtID"`          // Unique JWT ID
	Data           string `json:"data"`           // Custom data payload
}

// ParseToken uses a JWT token string to parse the token into a JWTToken struct
func (t *JWTToken) parseToken(tokenString string) JWTToken {

	// Decode token string into JWTToken struct
	decodedData, err := streaming.DecodeToByte(tokenString)
	if err != nil {
		log.Error("Error decoding JWT token: " + err.Error())
		log.Warn("Make sure the token is encoded in base64 for parsing")
		return JWTToken{}
	}

	// Unmarshal decoded data into JWTToken struct
	err = json.Unmarshal(decodedData, &t)
	if err != nil {
		log.Error("Error unmarshalling JWT token: " + err.Error())
		return JWTToken{}
	}

	return *t

}

// Get the expiration time of the token
func GetExpirationTime(tokenString string) (int64, error) {
	var jwtT JWTToken
	jwtT.parseToken(tokenString)
	if jwtT.Payload.ExpirationTime == 0 {
		err := errors.New("token invalid: could not parse token")
		return 0, err
	}
	return jwtT.Payload.ExpirationTime, nil
}

// Get the JWT ID of the token
func GetJwtID(tokenString string) (string, error) {
	var jwtT JWTToken
	jwtT.parseToken(tokenString)
	if jwtT.Payload.JwtID == "" {
		err := errors.New("token invalid: could not parse token")
		return "", err
	}
	return jwtT.Payload.JwtID, nil
}

// Get the subject of the token
func GetSubject(tokenString string) (string, error) {
	var jwtT JWTToken
	jwtT.parseToken(tokenString)
	if jwtT.Payload.Subject == "" {
		err := errors.New("token invalid: could not parse token")
		return "", err
	}
	return jwtT.Payload.Subject, nil
}

// Get the audience of the token
func GetAudience(tokenString string) (string, error) {
	var jwtT JWTToken
	jwtT.parseToken(tokenString)
	if jwtT.Payload.Audience == "" {
		err := errors.New("token invalid: could not parse token")
		return "", err
	}
	return jwtT.Payload.Audience, nil
}

// ValidateToken validates a JWT token against the provided issuer and audience.
// It returns true if the token is valid, and false otherwise, along with any error encountered.
func ValidateToken(targetTokenString, expectedIssuer, expectedAudience, timezone string) (bool, error) {

	var jwtT JWTToken

	// Parse target token
	jwtT.parseToken(targetTokenString)

	// Generate signature
	log.Debug("Validating signature")
	isValid, err := validateSignature(jwtT.Header.Algorithm, jwtT.Header, jwtT.Payload, jwtT.Signature)
	if err != nil {
		return false, err
	}

	if !isValid {
		err := errors.New("token invalid: signature mismatch")
		return false, err
	} else {
		log.Debug("Signature is valid")
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return false, fmt.Errorf("failed to load timezone: %w", err)
	}

	// Verify exp
	// Parse expiration time from epoch timestamp to RFC3339
	expTime, err := time.Parse(time.RFC3339, time.Unix(jwtT.Payload.ExpirationTime, 0).In(loc).Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("failed to parse expiration time: %w", err)
	}
	if time.Now().In(loc).After(expTime) {
		err := errors.New("token invalid: expired - Login required to refresh token")
		return false, err
	}

	// Verify iat
	// Parse issued at time from epoch timestamp to RFC3339
	iatTime, err := time.Parse(time.RFC3339, time.Unix(jwtT.Payload.IssuedAt, 0).In(loc).Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("failed to parse issued at time: %w", err)
	}
	if time.Now().Before(iatTime) {
		err := errors.New("token invalid: iat is in the future")
		return false, err
	}

	// Verify nbf
	// Parse not before time from epoch timestamp to RFC3339
	nbfTime, err := time.Parse(time.RFC3339, time.Unix(jwtT.Payload.NotBefore, 0).In(loc).Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("failed to parse not before time: %w", err)
	}
	if time.Now().Before(nbfTime) {
		err := errors.New("token invalid: nbf is in the future")
		return false, err
	}

	// Verify the audience
	if jwtT.Payload.Audience != expectedAudience {
		err := errors.New("token invalid: audience mismatch")
		return false, err
	}

	// Verify the issuer
	if jwtT.Payload.Issuer != expectedIssuer {
		err := errors.New("token invalid: issuer mismatch")
		return false, err
	}

	log.Debug("Token is valid")
	return true, nil
}

// generateSignature generates a signature for a JWT token based on the provided algorithm.
func generateSignature(algorithm JWTAlgorithm, header jwtTokenHeader, payload jwtTokenPayload) (string, error) {

	jsonHeaderByte, err := json.Marshal(header)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return "", err
	}

	jsonPayloadByte, err := json.Marshal(payload)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return "", err
	}

	// Create the data to sign (header + payload)
	var data []byte
	data = append(data, jsonHeaderByte...)
	data = append(data, jsonPayloadByte...)

	// Switch on the algorithm to determine the hash function
	switch algorithm {
	case HS256:
		// Get the key for the algorithm
		key, ok := keys[algorithm]
		if !ok {
			return "", errors.New("key not found for algorithm")
		}
		hasher := hmac.New(sha256.New, []byte(key))

		// Write the data to the HMAC hash
		_, err = hasher.Write(data)
		if err != nil {
			return "", fmt.Errorf("failed to write data to HMAC: %w", err)
		}

		// Compute the HMAC signature
		signature := hasher.Sum(nil)

		// Return the signature as a base64 URL encoded string
		return base64.RawURLEncoding.EncodeToString(signature), nil
	case RS256:
		x509PrivKey, err := base64.RawURLEncoding.DecodeString(keys[algorithm])
		if err != nil {
			return "", fmt.Errorf("failed to decode RSA key: %w", err)
		}
		privateKey, err := x509.ParsePKCS1PrivateKey(x509PrivKey)
		if err != nil {
			return "", fmt.Errorf("failed to parse RSA key: %w", err)
		}
		hashed := sha256.Sum256(data)
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(signature), nil

	case ES256:

		x509PrivKey, err := base64.RawURLEncoding.DecodeString(keys[algorithm])
		if err != nil {
			return "", fmt.Errorf("failed to decode ECDSA key: %w", err)
		}
		privateKey, err := x509.ParseECPrivateKey(x509PrivKey)
		if err != nil {
			return "", fmt.Errorf("failed to parse ECDSA key: %w", err)
		}
		hashed := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %w", err)
		}
		signature := append(r.Bytes(), s.Bytes()...)
		return base64.RawURLEncoding.EncodeToString(signature), nil
	default:
		return "", errors.New("unsupported algorithm: " + string(algorithm))
	}
}

// validateSignature validates the signature of a JWT token based on the provided algorithm.
func validateSignature(algorithm JWTAlgorithm, header jwtTokenHeader, payload jwtTokenPayload, signature string) (bool, error) {
	// Generate signature
	log.Debug("Validating signature")
	jsonHeaderByte, err := json.Marshal(header)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return false, err
	}

	jsonPayloadByte, err := json.Marshal(payload)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return false, err
	}

	// Create the data to sign (header + payload)
	var data []byte
	data = append(data, jsonHeaderByte...)
	data = append(data, jsonPayloadByte...)

	// Switch on the algorithm to determine the hash function
	switch algorithm {
	case HS256:
		// Get the key for the algorithm
		key, ok := keys[algorithm]
		if !ok {
			return false, errors.New("key not found for algorithm")
		}
		hasher := hmac.New(sha256.New, []byte(key))

		// Write the data to the HMAC hash
		_, err = hasher.Write(data)
		if err != nil {
			return false, fmt.Errorf("failed to write data to HMAC: %w", err)
		}

		// Compute the HMAC signature
		signatureBytes := hasher.Sum(nil)

		// Compare the generated signature with the provided signature
		if base64.RawURLEncoding.EncodeToString(signatureBytes) != signature {
			return false, errors.New("failed to verify HMAC signature")
		}

		return true, nil

	case RS256:

		signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
		if err != nil {
			return false, fmt.Errorf("failed to decode RSA signature: %w", err)
		}

		hashed := sha256.Sum256(data)

		x509PubKey, err := base64.RawURLEncoding.DecodeString(publicKeys[algorithm])
		if err != nil {
			return false, fmt.Errorf("failed to decode RSA public key: %w", err)
		}
		publicKey, err := x509.ParsePKIXPublicKey(x509PubKey)
		if err != nil {
			return false, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signatureBytes)
		if err != nil {
			return false, fmt.Errorf("failed to verify RSA signature: %w", err)
		}
		return true, nil

	case ES256:

		signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
		if err != nil {
			return false, fmt.Errorf("failed to decode ECDSA signature: %w", err)
		}

		x509PubKey, err := base64.RawURLEncoding.DecodeString(publicKeys[algorithm])
		if err != nil {
			return false, fmt.Errorf("failed to decode ECDSA public key: %w", err)
		}
		publicKey, err := x509.ParsePKIXPublicKey(x509PubKey)
		if err != nil {
			return false, fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
		hashed := sha256.Sum256(data)
		r := new(big.Int).SetBytes(signatureBytes[:len(signatureBytes)/2])
		s := new(big.Int).SetBytes(signatureBytes[len(signatureBytes)/2:])
		if !ecdsa.Verify(publicKey.(*ecdsa.PublicKey), hashed[:], r, s) {
			return false, errors.New("failed to verify ECDSA signature")
		}
		return true, nil

	default:
		return false, errors.New("unsupported algorithm: " + string(algorithm))
	}
}

// GenerateToken generates a JWT token with the specified algorithm and claims.
// It returns the encoded token, expiration time, and any error encountered.
func GenerateToken(algorithm JWTAlgorithm, timeZone string, timeoutPeriod string, issuer string, subject string, audience string, data string) (string, int64, error) {

	// Convert timeout period (in common time units) to seconds
	timeoutPeriodToDuration, err := time.ParseDuration(timeoutPeriod)
	if err != nil {
		log.Error("Error parsing timeout period: " + err.Error())
		return "", 0, err
	}
	// Convert time.Duration to seconds
	timeoutPeriodSeconds := int64(timeoutPeriodToDuration.Seconds())

	// Get current timestamp
	timestamp := int64(generator.EpochTimestamp(timeZone))

	// Calculate expiration time
	expirationtime := timestamp + timeoutPeriodSeconds

	// Calculate not before time
	notBefore := timestamp

	// Generate JWT ID
	jwtID := generator.RandomString(64)

	// Generate token
	newTokenData := JWTToken{}

	// Generate token
	newTokenData.Header.Algorithm = algorithm
	newTokenData.Header.Type = "JWT"
	newTokenData.Payload.ExpirationTime = expirationtime
	newTokenData.Payload.IssuedAt = timestamp
	newTokenData.Payload.NotBefore = notBefore
	newTokenData.Payload.Issuer = issuer
	newTokenData.Payload.Subject = subject
	newTokenData.Payload.Audience = audience
	newTokenData.Payload.JwtID = jwtID
	newTokenData.Payload.Data = data

	// Generate signature
	log.Debug("Generating signature")
	signature, err := generateSignature(algorithm, newTokenData.Header, newTokenData.Payload)
	if err != nil {
		return "", 0, err
	}

	newTokenData.Signature = signature

	// Marshal token data into byte array
	tokenData, err := json.Marshal(newTokenData)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return "", 0, err
	}

	// Encode token data into base64
	encodedTokenData := streaming.EncodeFromByte(tokenData)
	return encodedTokenData, expirationtime, nil
}
