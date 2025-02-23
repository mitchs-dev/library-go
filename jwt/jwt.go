// packageName: jwt

/*
Package jwt provides functions for JWT token manipulation
*/
package jwt

import (
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
	"hash"
	"time"

	"github.com/mitchs-dev/library-go/generator"
	"github.com/mitchs-dev/library-go/streaming"
	log "github.com/sirupsen/logrus"
)

// JWTAlgorithm is the algorithm used for JWT token generation
type JWTAlgorithm string

const (
	// HS256 is the HMAC SHA-256 algorithm
	HS256 = JWTAlgorithm("HS256")
	RS256 = JWTAlgorithm("RS256")
	ES256 = JWTAlgorithm("ES256")
)

type AlgoKeysStruct map[JWTAlgorithm]string
type PubKeysStruct map[JWTAlgorithm]string

var (
	keys           AlgoKeysStruct
	publicKeys     PubKeysStruct
	jwtInitialized bool
)

// InitializeJWT initializes the JWT token generation and validation
// If you would like to generate new keys, set generateKeys to true and existingKeys to nil
// If you would like to use existing keys, set generateKeys to false and provide the existing keys
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

// JWTToken struct for JWT token
type JWTToken struct {
	Header    jwtTokenHeader  `json:"header"`
	Payload   jwtTokenPayload `json:"payload"`
	Signature string          `json:"signature"`
}

// jwtTokenHeader struct for JWT token header
type jwtTokenHeader struct {
	Algorithm JWTAlgorithm `json:"algorithm"`
	Type      string       `json:"type"`
}

// jwtTokenPayload struct for JWT token payload
type jwtTokenPayload struct {
	// Stored in epoch timestamp
	ExpirationTime int64 `json:"expirationTime"`
	// Stored in epoch timestamp
	IssuedAt int64 `json:"issuedAt"`
	// Stored in epoch timestamp
	NotBefore int64  `json:"notBefore"`
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	Audience  string `json:"audience"`
	JwtID     string `json:"jwtID"`
	Data      string `json:"data"`
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
func (jwtT *JWTToken) GetExpirationTime(tokenString string) (int64, error) {

	jwtT.parseToken(tokenString)
	if jwtT.Payload.ExpirationTime == 0 {
		err := errors.New("token invalid: could not parse token")
		return 0, err
	}
	return jwtT.Payload.ExpirationTime, nil
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

// Validate token uses a JWT token string and a signing key to validate the token
func ValidateToken(targetTokenString, expectedIssuer, expectedAudience, timezone string) (bool, error) {

	var jwtT JWTToken

	// Parse target token
	jwtT.parseToken(targetTokenString)

	// Generate signature
	generatedSignature, err := generateSignature(jwtT.Header.Algorithm, jwtT.Header, jwtT.Payload)
	if err != nil {
		return false, err
	}

	// Compare generated signature with token signature
	if generatedSignature != jwtT.Signature {
		err := errors.New("token invalid: signature mismatch ")
		log.Debug("Got: " + generatedSignature)
		log.Debug("Expected: " + jwtT.Signature)
		return false, err
	} else {
		log.Debug("Signature is valid")
	}

	// Verify exp
	// Parse expiration time from epoch timestamp to RFC3339
	expTime, err := time.Parse(time.RFC3339, time.Unix(jwtT.Payload.ExpirationTime, 0).Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("failed to parse expiration time: %w", err)
	}
	if time.Now().After(expTime) {
		err := errors.New("token invalid: expired - Login required to refresh token")
		return false, err
	}

	// Verify iat
	// Parse issued at time from epoch timestamp to RFC3339
	iatTime, err := time.Parse(time.RFC3339, time.Unix(jwtT.Payload.IssuedAt, 0).Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("failed to parse issued at time: %w", err)
	}
	if time.Now().Before(iatTime) {
		err := errors.New("token invalid: iat is in the future")
		return false, err
	}

	// Verify nbf
	// Parse not before time from epoch timestamp to RFC3339
	nbfTime, err := time.Parse(time.RFC3339, time.Unix(jwtT.Payload.NotBefore, 0).Format(time.RFC3339))
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

func generateSignature(algorithm JWTAlgorithm, header jwtTokenHeader, payload jwtTokenPayload) (string, error) {

	// Get the key for the algorithm
	key, ok := keys[algorithm]
	if !ok {
		return "", errors.New("key not found for algorithm")
	}

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

	var hasher hash.Hash

	// Switch on the algorithm to determine the hash function
	switch algorithm {
	case HS256:
		hasher = hmac.New(sha256.New, []byte(key))
	case RS256:
		hasher = sha256.New()

	case ES256:
		hasher = sha256.New()
	default:
		hasher = sha256.New()
	}

	// Write the data to the HMAC hash
	_, err = hasher.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to HMAC: %w", err)
	}

	// Compute the HMAC signature
	signature := hasher.Sum(nil)

	// Return the signature as a base64 URL encoded string
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

// Generate token generates a JWT token and returns the encoded token data, token SHA256, and expiration time (in the respective order)
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
