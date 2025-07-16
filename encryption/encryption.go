/*
Package encryption provides functions for encrypting and decrypting data using AES-256-GCM.

Note: You MUST call InitEncryption before using any encryption functions.

Note 2: If you want to use Dislo for distributed locking, you need to call InitializeDisloLock with a valid DisloConfig. You can do this before or after Initializing encryption, but it MUST be done before you encrypt/decrypt. You can also delete a Dislo lock using DeleteDisloLock. For deletions, you can perform them any time as long as a DisloConfig is provided.
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mitchs-dev/dislo/pkg/sdk/client"
	log "github.com/sirupsen/logrus"
)

// errInvalidKeySize is returned when the provided key has an invalid size.
type errInvalidKeySize string

// keyMap is a map of keys to their corresponding AES-GCM ciphers.
type keyMap map[string]*struct {
	cipher cipher.AEAD
	locks  *keyLocks
}

type keyLocks struct {
	localLock sync.RWMutex
	unlocked  bool // Mainly for deferred unlocks
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
	localDisloMutexMap    disloMutexMap
	appKeyMapMutex        sync.Mutex
	initEncryptionOnce    sync.Once
	lockTimeout           = 5 * time.Second // Default timeout for Dislo locks
)

// A configuration struct for using Dislo for distributed locking.
type DisloConfig struct {
	Host          string
	Port          int
	SkipTLS       bool
	InstanceID    int
	Namespace     string
	DisloLockID   string
	DisloClientID uuid.UUID
	EncryptionKey []byte // This is only kept locally and not used in Dislo
}

type disloMutex struct {
	disloConfig *DisloConfig
	disloClient *client.ClientContext
}

type disloMutexMap map[string]*disloMutex

const aes256KeySize = 32

// If you want to use Dislo for distributed locking,
// you need to initialize it with the DisloConfig.
// If you do not, local mutex will be used for locking.
func InitializeDisloLock(disloConfigMap []*DisloConfig) {

	if len(disloConfigMap) == 0 {
		log.Debug("encryption: DisloConfig is not enabled or not set, using local mutex for locking")
	}

	// Initialize the Dislo client context
	log.Debug("encryption: Initializing Dislo for distributed locking")

	initDisloMutexMap := make(disloMutexMap)

	for _, disloConfig := range disloConfigMap {

		// Run validation checks on the DisloConfig
		if disloConfig.Host == "" {
			log.Fatal("encryption: DisloConfig Host is required")
		}
		if disloConfig.Port <= 0 {
			log.Fatal("encryption: DisloConfig Port must be a positive integer")
		}
		if disloConfig.InstanceID <= 0 {
			log.Fatal("encryption: DisloConfig InstanceID must be a positive integer")
		}
		if disloConfig.DisloClientID == uuid.Nil {
			log.Fatal("encryption: DisloConfig DisloClientID must be a valid UUID")
		}
		if disloConfig.EncryptionKey == nil {
			log.Fatal("encryption: DisloConfig EncryptionKey is required")
		}

		newClient := client.NewContext(
			disloConfig.Host,
			disloConfig.Port,
			disloConfig.SkipTLS,
			disloConfig.InstanceID,
			disloConfig.DisloClientID,
		)

		if newClient == nil {
			log.Fatalf("encryption: Failed to create Dislo client for %s:%d", disloConfig.Host, disloConfig.Port)
		}

		initDisloMutexMap[string(disloConfig.EncryptionKey)] = &disloMutex{
			disloConfig: disloConfig,
			disloClient: newClient,
		}

		correlationID := "enc.init." + disloConfig.DisloLockID + "." + disloConfig.Namespace + uuid.New().String()
		err := newClient.Create(disloConfig.DisloLockID, disloConfig.Namespace, correlationID)
		if err != nil {
			if strings.Contains(err.Error(), "LOCK_ALREADY_EXISTS") {
				log.Debugf("encryption: Dislo lock exists for ID: %s", disloConfig.DisloLockID)
			} else {
				log.Fatalf("encryption: Failed to create Dislo lock: %v", err)
			}
		}

		log.Debugf("encryption: Dislo lock initialized for ID: %s", disloConfig.DisloLockID)
	}

	if localDisloMutexMap == nil {
		localDisloMutexMap = initDisloMutexMap
	} else {
		// Merge the new Dislo mutex map with the existing one
		for key, value := range initDisloMutexMap {
			_, ok := localDisloMutexMap[key]
			if !ok {
				localDisloMutexMap[key] = value
			} else {
				log.Warnf("encryption: Dislo lock for key %s already exists, skipping initialization", key)
			}
		}
	}

	log.Debugf("encryption: Dislo locks initialized with %d keys", len(localDisloMutexMap))
}

// DeleteDisloLock deletes a Dislo lock for the given DisloConfig.
func DeleteDisloLock(disloConfig *DisloConfig) error {
	if disloConfig == nil {
		return fmt.Errorf("encryption: DisloConfig is nil")
	}

	// Run validation checks on the DisloConfig
	if disloConfig.Host == "" {
		log.Fatal("encryption: DisloConfig Host is required")
	}
	if disloConfig.Port <= 0 {
		log.Fatal("encryption: DisloConfig Port must be a positive integer")
	}
	if disloConfig.InstanceID <= 0 {
		log.Fatal("encryption: DisloConfig InstanceID must be a positive integer")
	}
	if disloConfig.DisloClientID == uuid.Nil {
		log.Fatal("encryption: DisloConfig DisloClientID must be a valid UUID")
	}
	if disloConfig.EncryptionKey == nil {
		log.Fatal("encryption: DisloConfig EncryptionKey is required")
	}
	if disloConfig.DisloLockID == "" {
		log.Fatal("encryption: DisloConfig DisloLockID is required")
	}
	if disloConfig.Namespace == "" {
		log.Fatal("encryption: DisloConfig Namespace is required")
	}

	log.Debugf("encryption: Deleting Dislo lock for ID: %s", disloConfig.DisloLockID)
	log.Debugf("encryption: Namespace: %s", disloConfig.Namespace)

	// We create a new Dislo client context for instances
	// where a local map may not exist
	disloClient := client.NewContext(
		disloConfig.Host,
		disloConfig.Port,
		disloConfig.SkipTLS,
		disloConfig.InstanceID,
		disloConfig.DisloClientID,
	)

	err := disloClient.Delete(disloConfig.DisloLockID, disloConfig.Namespace)
	if err != nil {
		log.Errorf("encryption: failed to acquire Dislo lock for deletion: %v", err)
	}

	_, ok := localDisloMutexMap[string(disloConfig.EncryptionKey)]

	// This is to avoid a nil pointer if just trying to delete the lock in dislo
	// and the local map hasn't been initialized
	if ok {
		delete(localDisloMutexMap, string(disloConfig.EncryptionKey))
	}

	log.Debugf("encryption: Dislo lock with ID %s deleted", disloConfig.DisloLockID)

	return err
}

// InitEncryption should be run before any (de)encryption operations.
func InitEncryption(setNoncePoolSize int) {
	initEncryptionOnce.Do(func() {
		if noncePoolSize == 0 {
			noncePoolSize = noncePoolSizeDefault
		} else {
			noncePoolSize = setNoncePoolSize
		}
		appKeyMap = newKeyMap()
		log.Debugf("Encryption initialized with nonce pool size: %d", noncePoolSize)
		encryptionInitialized = true
	})
}

// Lock acquires a lock for the key map.
// Logically uses local mutex or Dislo distributed lock based on the configuration.
func (l *keyLocks) lock(key []byte) error {

	log.Debug("encryption: Acquiring lock")

	disloMutex, ok := localDisloMutexMap[string(key)]
	if !ok {
		// If we don't have a Dislo lock, we can use the local mutex
		log.Debug("encryption: Using local mutex for locking")
		l.localLock.Lock()
	} else {
		log.Debugf("encryption: Using Dislo for distributed locking (%s:%d:%s.%s)", disloMutex.disloConfig.DisloClientID.String(), disloMutex.disloConfig.InstanceID, disloMutex.disloConfig.Namespace, disloMutex.disloConfig.DisloLockID)
		correlationID := "enc.lock." + disloMutex.disloConfig.DisloLockID + "." + disloMutex.disloConfig.Namespace + uuid.New().String()
		if err := disloMutex.disloClient.Lock(disloMutex.disloConfig.DisloLockID, disloMutex.disloConfig.Namespace, correlationID); err != nil {
			l.unlocked = true // We set unlocked to avoid a local deadlock
			return fmt.Errorf("encryption: failed to acquire Dislo lock: %w", err)
		}
		localDisloMutexMap[string(key)] = disloMutex // Store the Dislo mutex in the local map
	}

	// Set unlocked to false as we have acquired the lock
	l.unlocked = false

	log.Debug("encryption: Lock acquired")

	return nil
}

// Unlock releases the lock for the key map.
// Logically uses local or Dislo mutex based on the configuration.
func (l *keyLocks) unlock(key []byte) error {

	log.Debug("encryption: Releasing lock")

	if !l.unlocked {
		disloMutex, ok := localDisloMutexMap[string(key)]
		if !ok {
			// If we don't have a Dislo lock, we can use the local mutex
			log.Debug("encryption: Using local mutex for unlocking")
			l.localLock.Unlock()
		} else {
			log.Debugf("encryption: Using Dislo for distributed locking (%s:%d:%s.%s)", disloMutex.disloConfig.DisloClientID.String(), disloMutex.disloConfig.InstanceID, disloMutex.disloConfig.Namespace, disloMutex.disloConfig.DisloLockID)
			correlationID := "enc.unlock." + disloMutex.disloConfig.DisloLockID + "." + disloMutex.disloConfig.Namespace + uuid.New().String()
			if err := disloMutex.disloClient.Unlock(disloMutex.disloConfig.DisloLockID, disloMutex.disloConfig.Namespace, correlationID); err != nil {
				l.unlocked = true // We set unlocked to avoid a local deadlock
				return fmt.Errorf("encryption: failed to release Dislo lock: %w", err)
			}
			log.Debug("encryption: Dislo lock released")
		}
	}
	// Set unlocked lock is truly released
	l.unlocked = true

	log.Debug("encryption: Lock released")

	return nil
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

	appKeyMapMutex.Lock()
	keyValMapKey, ok := appKeyMap[string(key)]
	var aesgcm cipher.AEAD
	if !ok {
		log.Debug("encryption: Key not found, initializing cipher")
		aesgcm, err := initCipher(key)
		if err != nil {
			appKeyMapMutex.Unlock()
			log.Errorf("encryption: Failed to initialize cipher: %v", err)
			return nil, fmt.Errorf("encryption: failed to initialize cipher: %w", err)
		} else {
			log.Debugf("encryption: Cipher initialized")
			keyValMapKey = &struct {
				cipher cipher.AEAD
				locks  *keyLocks
			}{
				cipher: aesgcm,
				locks:  &keyLocks{},
			}
			appKeyMap[string(key)] = keyValMapKey

		}
	} else {
		log.Debug("encryption: Key found")
	}
	appKeyMapMutex.Unlock()

	aesgcm = keyValMapKey.cipher
	log.Debugf("encryption: Cipher set")

	if keyValMapKey.locks == nil {
		return nil, fmt.Errorf("encryption: locks not initialized for key %s", string(key))
	}
	if err := keyValMapKey.locks.lock(key); err != nil {
		return nil, err
	}
	defer func() {
		if err := keyValMapKey.locks.unlock(key); err != nil {
			log.Error(err)
		}
	}()

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

	appKeyMapMutex.Lock()
	keyValMapKey, ok := appKeyMap[string(key)]
	var aesgcm cipher.AEAD
	if !ok {
		log.Debug("encryption: Key not found, initializing cipher")
		aesgcm, err := initCipher(key)
		if err != nil {
			appKeyMapMutex.Unlock()
			log.Errorf("encryption: Failed to initialize cipher: %v", err)
			return nil, fmt.Errorf("encryption: failed to initialize cipher: %w", err)
		} else {
			log.Debugf("encryption: Cipher initialized")
			keyValMapKey = &struct {
				cipher cipher.AEAD
				locks  *keyLocks
			}{
				cipher: aesgcm,
				locks:  &keyLocks{},
			}
			appKeyMap[string(key)] = keyValMapKey

		}
	} else {
		log.Debug("encryption: Key found")
	}
	appKeyMapMutex.Unlock()

	aesgcm = keyValMapKey.cipher
	log.Debugf("encryption: Cipher set")
	if keyValMapKey.locks == nil {
		return nil, fmt.Errorf("encryption: locks not initialized for key %s", string(key))
	}
	if err := keyValMapKey.locks.lock(key); err != nil {
		return nil, err
	}
	defer func() {
		if err := keyValMapKey.locks.unlock(key); err != nil {
			log.Error(err)
		}
	}()

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

	appKeyMapMutex.Lock()
	keyValMapKey, ok := appKeyMap[string(key)]
	if !ok {
		appKeyMapMutex.Unlock()
		return nil, fmt.Errorf("decryption: key not found")
	}

	log.Debug("decryption: Key found")
	aesgcm = keyValMapKey.cipher
	if aesgcm == nil {
		appKeyMapMutex.Unlock()
		return nil, fmt.Errorf("decryption: cipher not found")
	}
	appKeyMapMutex.Unlock()

	if keyValMapKey.locks == nil {
		return nil, fmt.Errorf("encryption: locks not initialized for key %s", string(key))
	}
	if err := keyValMapKey.locks.lock(key); err != nil {
		return nil, err
	}
	defer func() {
		if err := keyValMapKey.locks.unlock(key); err != nil {
			log.Error(err)
		}
	}()

	var ciphertextBytes []byte

	// Ensure that the ciphertext is in the correct format
	if usedBinaryData {
		ciphertextBytes, ok := ciphertext.([]byte)
		if !ok {
			return nil, fmt.Errorf("decryption: ciphertext must be []byte when using binary data, got %T", ciphertext)
		}
		log.Debugf("decryption: Ciphertext is []byte, length: %d", len(ciphertextBytes))

		if len(ciphertextBytes) < 8+nonceSize {
			return nil, fmt.Errorf("decryption: ciphertext too short")
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
	log.Debug("Initializing cipher for key")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	log.Debug("Creating GCM")
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize = aesgcm.NonceSize()
	log.Debug("Returning cipher")
	return aesgcm, nil
}
