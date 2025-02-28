/*
Package encryption provides functions for encrypting and decrypting data using AES-256-GCM.

Note: You MUST call InitEncryption before using any encryption functions.
*/
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// errInvalidKeySize is returned when the provided key has an invalid size.
type errInvalidKeySize string

// keyMap is a map of keys to their corresponding AES-GCM ciphers.
type keyMap map[string]struct {
	cipher cipher.AEAD
	lock   sync.Mutex
}

func (e errInvalidKeySize) Error() string {
	return string(e)
}

var (
	invalidKeySizeError = errInvalidKeySize("encryption: invalid key size")
	// aesgcm is the AES-GCM cipher.
	aesgcm                cipher.AEAD
	nonceSize             int
	noncePool             [][]byte
	noncePoolIndex        int
	noncePoolMutex        sync.Mutex
	noncePoolSize         int
	sequenceCounter       uint64
	noncePoolSizeDefault  = 1024
	encryptionInitialized bool
	appKeyMap             keyMap
)

const aes256KeySize = 32

// InitEncryption should be run before any (de)encryption operations.
func InitEncryption(setNoncePoolSize int) {
	if noncePoolSize == 0 {
		noncePoolSize = noncePoolSizeDefault
	} else {
		noncePoolSize = setNoncePoolSize
	}
	// Make the key map
	appKeyMap = newKeyMap()
	log.Debugf("Encryption initialized with nonce pool size: %d", noncePoolSize)
	encryptionInitialized = true
}

/*
	Encrypt encrypts the given plaintext using AES-256-GCM with the provided key.

The key should be 32 bytes (256 bits) for AES-256.
If useBinaryData is true, the ciphertext will be returned as a byte slice.
The return will be in the format of string (useBinaryData = false) or []byte (useBinaryData = true).
This function is probabilistic, meaning that the same plaintext and key will not always result in the same ciphertext.
If you need deterministic encryption, use EncryptDeterministic instead.
*/
func Encrypt(plaintext []byte, key []byte, useBinaryData bool) (interface{}, error) {
	if !encryptionInitialized {
		return nil, fmt.Errorf("encryption: encryption not initialized")
	}

	keyValMapKey, ok := appKeyMap[string(key)]

	log.Debug("encryption: Acquiring lock")
	keyValMapKey.lock.Lock()
	log.Debug("encryption: Lock acquired")
	var aesgcm cipher.AEAD
	if !ok {
		log.Debug("encryption: Key not found, initializing cipher")
		aesgcm, err := initCipher(key)
		if err != nil {
			log.Fatalf("encryption: Failed to initialize cipher: %v", err)
		} else {
			log.Debugf("encryption: Cipher initialized")
			keyValMapKey.cipher = aesgcm
			keyValMapKey.lock.Unlock()
			log.Debug("encryption: Lock released")
			appKeyMap[string(key)] = keyValMapKey

		}
	} else {
		log.Debug("encryption: Key found")
	}
	aesgcm = keyValMapKey.cipher
	log.Debugf("encryption: Cipher set")

	initNoncePool(aesgcm.NonceSize())
	log.Debug("encryption: Nonce pool initialized")

	if len(key) != aes256KeySize {
		return nil, invalidKeySizeError
	}
	log.Debug("encryption: Key size checked")

	nonce := getNonce(nonceSize)
	log.Debugf("Nonce: %v", nonce)
	sequenceNumber := getNextSequenceNumber()
	aad := make([]byte, 8)
	binary.LittleEndian.PutUint64(aad, sequenceNumber)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	// Append the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)

	// Append the AAD to the ciphertext
	ciphertextWithAAD := append(aad, ciphertext...)

	// If you want to simply return the ciphertext as a byte slice
	// or if you want to encode it with hex
	if useBinaryData {
		log.Debug("Returning binary data")
		return ciphertextWithAAD, nil
	} else {
		log.Debug("Returning encoded data")
		// Encode with Hex over b64 for performance reasons
		encodedHex := hex.EncodeToString(ciphertextWithAAD)
		return encodedHex, nil
	}
}

/*
EncryptDeterministic encrypts the given plaintext using AES-256-GCM with the provided key.

This function is deterministic, meaning that the same plaintext and key will always result in the same ciphertext.
If you need probabilistic encryption, use Encrypt instead.
*/
func EncryptDeterministic(plaintext []byte, key []byte, useBinaryData bool) (interface{}, error) {
	if !encryptionInitialized {
		return nil, fmt.Errorf("encryption: encryption not initialized")
	}

	keyValMapKey, ok := appKeyMap[string(key)]

	log.Debugf("encryption: Acquiring lock")
	keyValMapKey.lock.Lock()
	log.Debugf("encryption: Lock acquired")
	var aesgcm cipher.AEAD
	if !ok {
		log.Debugf("encryption: Key not found, initializing cipher")
		aesgcm, err := initCipher(key)
		if err != nil {
			log.Fatalf("encryption: Failed to initialize cipher: %v", err)
		} else {
			log.Debugf("encryption: Cipher initialized")
			keyValMapKey.cipher = aesgcm
			keyValMapKey.lock.Unlock()
			log.Debugf("encryption: Lock released")
			appKeyMap[string(key)] = keyValMapKey

		}
	} else {
		log.Debugf("encryption: Key found")
	}
	aesgcm = keyValMapKey.cipher
	log.Debugf("encryption: Cipher set")

	initNoncePool(aesgcm.NonceSize())
	log.Debugf("encryption: Nonce pool initialized")

	if len(key) != aes256KeySize {
		return nil, invalidKeySizeError
	}
	log.Debugf("encryption: Key size checked")

	var nonce []byte
	// Deterministic nonce: use a hash of the key and plaintext
	// This is a simplified example; consider using HKDF for better security.
	nonce = make([]byte, aesgcm.NonceSize())
	h := sha256.Sum256(append(key, plaintext...))
	copy(nonce, h[:aesgcm.NonceSize()])

	log.Debugf("Nonce: %v", nonce)
	// sequenceNumber := getNextSequenceNumber() // Removed
	aad := make([]byte, 8)
	binary.LittleEndian.PutUint64(aad, 0) // Always use 0 for deterministic
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	// Append the nonce to the ciphertext
	ciphertext = append(nonce, ciphertext...)

	// Append the AAD to the ciphertext
	ciphertextWithAAD := append(aad, ciphertext...)

	// If you want to simply return the ciphertext as a byte slice
	// or if you want to encode it with hex
	if useBinaryData {
		log.Debugf("Returning binary data")
		return ciphertextWithAAD, nil
	} else {
		log.Debugf("Returning encoded data")
		// Encode with Hex over b64 for performance reasons
		encodedHex := hex.EncodeToString(ciphertextWithAAD)
		return encodedHex, nil
	}
}

/*
	Decrypt decrypts the given ciphertext using AES-256-GCM with the provided key.

The key should be 32 bytes (256 bits) for AES-256.
If usedBinaryData is true, the ciphertext should be a byte slice or it will return an error.
Unlike Encrypt, decrypt is going to return the plaintext as a byte slice.
*/
func Decrypt(ciphertext interface{}, key []byte, usedBinaryData bool) ([]byte, error) {
	log.Debug("Decrypting")
	if !encryptionInitialized {
		return nil, fmt.Errorf("encryption: encryption not initialized")
	}

	if len(key) != aes256KeySize {
		return nil, invalidKeySizeError
	}

	var err error

	log.Debug("decryption: Retrieving key")
	keyValMapKey, ok := appKeyMap[string(key)]

	log.Debug("decryption: Acquiring lock")
	keyValMapKey.lock.Lock()
	log.Debug("decryption: Lock acquired")
	if !ok {
		return nil, fmt.Errorf("decryption: key not found")
	}
	log.Debug("decryption: Key found")
	aesgcm = keyValMapKey.cipher
	if aesgcm == nil {
		return nil, fmt.Errorf("decryption: cipher not found")
	}
	log.Debug("decryption: Cipher set")

	keyValMapKey.lock.Unlock()
	log.Debug("decryption: Lock released")

	var ciphertextBytes []byte

	// Ensure that the ciphertext is in the correct format
	if usedBinaryData {
		ciphertextBytes, ok := ciphertext.([]byte)
		if !ok {
			return nil, fmt.Errorf("decryption: ciphertext must be []byte when using binary data, got %T", ciphertext)
		}
		log.Debugf("decryption: Ciphertext is []byte, length: %d", len(ciphertextBytes))

		aad := ciphertextBytes[:8]
		ciphertextBytes = ciphertextBytes[8:]
		nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
		log.Debugf("Nonce: %v", nonce)
		plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, aad)
		if err != nil {
			return nil, fmt.Errorf("decryption: failed to decrypt: %w", err)
		}
		return plaintext, nil
	} else {
		ciphertextString, ok := ciphertext.(string)
		if !ok {
			return nil, fmt.Errorf("decryption: ciphertext must be string when using text data, got %T", ciphertext)
		}
		log.Debugf("decryption: Ciphertext is string, length: %d", len(ciphertextString))
		ciphertextBytes, err = hex.DecodeString(ciphertextString)
		if err != nil {
			return nil, fmt.Errorf("decryption: failed to decode base64: %w", err)
		}

		aad := ciphertextBytes[:8]
		ciphertextBytes = ciphertextBytes[8:]
		nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
		log.Debugf("Nonce: %v", nonce)
		plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, aad)
		if err != nil {
			return nil, fmt.Errorf("decryption: failed to decrypt: %w", err)
		}
		return plaintext, nil
	}
}

// GenerateRandomKey generates a random key of the specified length.
// For AES-256, the length should be 32 bytes.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, aes256KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, fmt.Errorf("key generation: failed to read random bytes: %w", err)
	}
	return key, nil
}

// initNoncePool initializes the nonce pool with random nonces.
func initNoncePool(nonceSize int) {
	noncePool = make([][]byte, noncePoolSize)
	for i := 0; i < noncePoolSize; i++ {
		noncePool[i] = make([]byte, nonceSize)
		_, err := io.ReadFull(rand.Reader, noncePool[i])
		if err != nil {
			log.Fatalf("Failed to initialize nonce pool: %v", err)
		}
	}
}

// getNonce returns a random nonce from the pool.
func getNonce(nonceSize int) []byte {
	noncePoolMutex.Lock()
	defer noncePoolMutex.Unlock()

	nonce := noncePool[noncePoolIndex]
	noncePoolIndex = (noncePoolIndex + 1) % noncePoolSize

	// Refill the pool if it's getting low.
	// This is important to avoid a situation where all concurrent requests try to refill it.
	if noncePoolIndex == 0 {
		go refillNoncePool(nonceSize)
	}

	return nonce
}

// refillNoncePool refills the nonce pool with fresh random nonces.
func refillNoncePool(nonceSize int) {
	noncePoolMutex.Lock()
	defer noncePoolMutex.Unlock()
	for i := 0; i < noncePoolSize; i++ {
		if noncePool[i] == nil {
			noncePool[i] = make([]byte, nonceSize)
			_, err := io.ReadFull(rand.Reader, noncePool[i])
			if err != nil {
				log.Errorf("Failed to refill nonce pool: %v", err)
			}
		}
	}
}

// getNextSequenceNumber returns the next sequence number.
func getNextSequenceNumber() uint64 {
	return atomic.AddUint64(&sequenceCounter, 1)
}

// newKeyMap returns a new key map.
func newKeyMap() keyMap {
	return make(keyMap)
}

// initCipher initializes the AES cipher with the provided key.
func initCipher(key []byte) (cipher.AEAD, error) {
	var aesgcm cipher.AEAD
	var initErr error
	var once sync.Once

	once.Do(func() {
		log.Debug("Initializing cipher for key")
		block, err := aes.NewCipher(key)
		if err != nil {
			initErr = fmt.Errorf("failed to create cipher: %w", err)
			return
		}
		log.Debug("Creating GCM")
		newAesgcm, err := cipher.NewGCM(block)
		if err != nil {
			initErr = fmt.Errorf("failed to create GCM: %w", err)
			return
		}

		aesgcm = newAesgcm
		nonceSize = aesgcm.NonceSize()
	})
	log.Debug("Returning cipher")
	if initErr != nil {
		return nil, initErr
	}

	return aesgcm, nil
}
