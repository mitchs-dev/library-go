// packageName: jwt

/*
Package jwt provides functions for JWT token manipulation
*/
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
var jwtS JWTToken

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
func ValidateToken(targetTokenString, sourceTokenString, tokenSHA256, signingKey string) (bool, error) {

	// Parse target token
	jwtT.parseToken(targetTokenString)

	// Parse source token
	jwtS.parseToken(sourceTokenString)

	// Verify token was parsed correctly
	if jwtT.Payload.JwtID != jwtS.Payload.JwtID {
		err := errors.New("token invalid: JWT ID mismatch")
		return false, err
	} else {
		log.Debug("JWT ID is valid")
	}

	// Verify the token audience
	if jwtT.Payload.Audience != jwtS.Payload.Audience {
		err := errors.New("token invalid: audience mismatch")
		return false, err
	} else {
		log.Debug("Audience is valid")
	}

	// Verify the token issuer
	if jwtT.Payload.Issuer != jwtS.Payload.Issuer {
		err := errors.New("token invalid: issuer mismatch")
		return false, err
	} else {
		log.Debug("Issuer is valid")
	}

	jwtPayloadJSON, err := json.Marshal(jwtT.Payload)
	if err != nil {
		return false, err
	}

	jwtHeaderJSON, err := json.Marshal(jwtT.Header)
	if err != nil {
		return false, err
	}
	// Generate signature
	generatedSignature, err := generateSignature(signingKey, string(jwtHeaderJSON), string(jwtPayloadJSON))
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

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(targetTokenString))
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

func generateSignature(signingKey string, header string, payload string) (string, error) {
	// Create a new HMAC hash using SHA256
	h := hmac.New(sha256.New, []byte(signingKey))

	// Create the data to sign (header + payload)
	data := header + "." + payload

	// Write the data to the HMAC hash
	_, err := h.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to write data to HMAC: %w", err)
	}

	// Compute the HMAC signature
	signature := h.Sum(nil)

	// Return the signature as a base64 URL encoded string
	return base64.RawURLEncoding.EncodeToString(signature), nil
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
	newTokenData := JWTToken{}

	// Generate token
	newTokenData.Header.Algorithm = "HS256"
	newTokenData.Header.Type = "JWT"
	newTokenData.Payload.ExpirationTime = expirationtime
	newTokenData.Payload.IssuedAt = timestamp
	newTokenData.Payload.Issuer = issuer
	newTokenData.Payload.Subject = subject
	newTokenData.Payload.Audience = audience
	newTokenData.Payload.JwtID = jwtID
	newTokenData.Payload.Data = data

	// Marshal token data into byte array
	tokenDataHeaderJSON, err := json.Marshal(newTokenData.Header)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return "", "", 0, err
	}

	tokenDataPayloadJSON, err := json.Marshal(newTokenData.Payload)
	if err != nil {
		log.Error("Error marshalling token data: " + err.Error())
		return "", "", 0, err
	}

	// Generate signature
	signature, err := generateSignature(signingKey, string(tokenDataHeaderJSON), string(tokenDataPayloadJSON))
	if err != nil {
		return "", "", 0, err
	}

	newTokenData.Signature = signature

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
