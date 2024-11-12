// Packge name: encryption
/*
This package provides a simple method of encrypting and decrypting strings using key which can be generated using the GenerateKey() function.
*/
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

func GenerateKey() string {
	// Generate a 64-byte key.
	currentTime := time.Now().String()
	hash := sha256.New()
	hash.Write([]byte(currentTime))
	key64 := hash.Sum(nil)
	// Use HKDF to derive a 32-byte key from the 64-byte key.
	hkdf := hkdf.New(sha256.New, key64, nil, nil)
	key32 := make([]byte, 32)
	io.ReadFull(hkdf, key32)
	// Base64 URL encode the key.
	return strings.ReplaceAll(base64.URLEncoding.EncodeToString(key32), "=", "")
}

func deriveKey(inputKey string) ([]byte, error) {
	byteInputKey := []byte(inputKey)
	hkdf := hkdf.New(sha256.New, byteInputKey, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	return key, nil
}

func Encrypt(plainText string, key string, iv []byte) (string, error) {
	derivedKey, err := deriveKey(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	b := []byte(plainText)
	ciphertext := make([]byte, aes.BlockSize+len(b))

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], b)

	return hex.EncodeToString(ciphertext), nil
}

func Decrypt(cipherText string, key string) (string, error) {
	derivedKey, err := deriveKey(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	decodedCipherText, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	if len(decodedCipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := decodedCipherText[:aes.BlockSize]
	decodedCipherText = decodedCipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decodedCipherText, decodedCipherText)

	return string(decodedCipherText), nil
}
