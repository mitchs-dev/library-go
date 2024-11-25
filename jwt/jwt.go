// packageName: jwt

/*
Package jwt provides functions for JWT token manipulation
*/
package jwt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/mitchs-dev/library-go/generator"
	"github.com/mitchs-dev/library-go/streaming"
	log "github.com/sirupsen/logrus"
)

// JWTToken struct for JWT token
type JWTToken struct {
	Header struct {
		Algorithm string `json:"algorithm"`
		Type      string `json:"type"`
	} `json:"header"`
	Payload struct {
		ExpirationTime int64  `json:"expirationTime"`
		IssuedAt       int64  `json:"issuedAt"`
		Issuer         string `json:"issuer"`
		Subject        string `json:"subject"`
		Audience       string `json:"audience"`
		JwtID          string `json:"jwtID"`
		Data           string `json:"data"`
	} `json:"payload"`
	Signature string `json:"signature"`
}

var jwtT JWTToken

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
	jwtT.parseToken(tokenString)
	if jwtT.Payload.ExpirationTime == 0 {
		err := errors.New("token invalid: could not parse token")
		return 0, err
	}
	return jwtT.Payload.ExpirationTime, nil
}

// Get the audience of the token
func GetAudience(tokenString string) (string, error) {
	jwtT.parseToken(tokenString)
	if jwtT.Payload.Audience == "" {
		err := errors.New("token invalid: could not parse token")
		return "", err
	}
	return jwtT.Payload.Audience, nil
}

// Validate token uses a JWT token string and a signing key to validate the token
func ValidateToken(tokenString string, tokenSHA256 string, signingKey string) (bool, error) {

	// Parse token
	jwtT.parseToken(tokenString)

	// Verify token was parsed correctly
	if jwtT.Payload.JwtID == "" {
		err := errors.New("token invalid: could not parse token")
		return false, err
	}

	// Generate signature
	generatedSignature := generateSignature(signingKey, jwtT.Payload.JwtID)

	// Compare generated signature with token signature
	if generatedSignature != jwtT.Signature {
		err := errors.New("token invalid: signature mismatch")
		return false, err
	}

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(tokenString))
	generatedTokenSHA256 := "0x" + hex.EncodeToString(hash[:])

	log.Debug("Provided token SHA256: " + tokenSHA256)
	log.Debug("Generated token SHA256: " + generatedTokenSHA256)

	// Verify token SHA256
	if tokenSHA256 != generatedTokenSHA256 {
		err := errors.New("token invalid: SHA256 mismatch")
		return false, err
	}

	// Verify token expiration time
	if jwtT.Payload.ExpirationTime < int64(generator.EpochTimestamp("UTC")) {
		err := errors.New("token invalid: expired - Login required to refresh token")
		return false, err
	}

	// Verify token timeout timestamp

	log.Debug("Token is valid")
	return true, nil
}

// Generate Signature uses a Signing Key and a JWT token string to generate a signature
func generateSignature(signingKey string, jwtID string) string {

	saltedBytes := []byte(signingKey + jwtID)
	hash := sha256.Sum256(saltedBytes)
	return hex.EncodeToString(hash[:])

}

// Generate token generates a JWT token and returns the encoded token data, token SHA256, and expiration time (in the respective order)
func GenerateToken(signingKey string, timeZone string, timeoutPeriod string, issuer string, subject string, audience string, data string) (string, string, int64, error) {

	// Convert timeout period (in common time units) to seconds
	timeoutPeriodToDuration, err := time.ParseDuration(timeoutPeriod)
	if err != nil {
		log.Error("Error parsing timeout period: " + err.Error())
		return "", "", 0, err
	}
	// Convert time.Duration to seconds
	timeoutPeriodSeconds := int64(timeoutPeriodToDuration.Seconds())

	timestamp := int64(generator.EpochTimestamp(timeZone))

	// Calculate expiration time
	expirationtime := timestamp + timeoutPeriodSeconds

	// Generate JWT ID
	jwtID := generator.RandomString(64)

	// Generate token
	newTokenData := JWTToken{
		Header: struct {
			Algorithm string `json:"algorithm"`
			Type      string `json:"type"`
		}{
			Algorithm: "HS256",
			Type:      "JWT",
		},
		Payload: struct {
			ExpirationTime int64  `json:"expirationTime"`
			IssuedAt       int64  `json:"issuedAt"`
			Issuer         string `json:"issuer"`
			Subject        string `json:"subject"`
			Audience       string `json:"audience"`
			JwtID          string `json:"jwtID"`
			Data           string `json:"data"`
		}{
			ExpirationTime: expirationtime,
			IssuedAt:       timestamp,
			Issuer:         issuer,
			Subject:        subject,
			Audience:       audience,
			JwtID:          jwtID,
			Data:           data,
		},
		Signature: generateSignature(signingKey, jwtID),
	}

	// Marshal token data into byte array
	tokenData, err := json.Marshal(newTokenData)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return "", "", 0, err
	}

	// Encode token data into base64
	encodedTokenData := streaming.EncodeFromByte(tokenData)

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(encodedTokenData))
	tokenSHA256 := "0x" + hex.EncodeToString(hash[:])

	return encodedTokenData, tokenSHA256, expirationtime, nil
}
