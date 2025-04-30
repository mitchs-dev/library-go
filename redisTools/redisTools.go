// Package name: redisTools

/*
Package redisTools provides a wrapper functions for Redis database interactions.
*/
package redisTools

import (
	"errors"
	"time"

	"github.com/go-redis/redis"
	"github.com/mitchs-dev/library-go/encryption"
	"github.com/mitchs-dev/library-go/generator"
)

// RedisConfiguration struct for Redis configuration
type RedisConfiguration struct {
	Host       RedisConfigHost
	Encryption RedisConfigEncryption
}

type RedisConfigEncryption struct {
	Key []byte
}

type RedisConfigHost struct {
	Addr     string
	Password string
	DB       int
}

// RedisClient struct for Redis client
type RedisClient struct {
	client *redis.Client
	config RedisConfiguration
}

// NewRedisClient returns a new Redis client
func NewRedisClient(config RedisConfiguration) *RedisClient {
	return &RedisClient{
		client: redis.NewClient(RedisOptions(config)),
		config: config,
	}
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// RedisOptions returns a new Redis options struct
func RedisOptions(redisConfig RedisConfiguration) *redis.Options {
	return &redis.Options{
		Addr:     redisConfig.Host.Addr,
		Password: redisConfig.Host.Password,
		DB:       redisConfig.Host.DB,
	}
}

// TestConnection tests the connection to Redis
func TestConnection(redisConfig RedisConfiguration) error {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	_, err := client.client.Ping().Result()
	return err
}

// TestAccess tests the access to Redis
func TestAccess(redisConfig RedisConfiguration) error {
	client := NewRedisClient(redisConfig)
	defer client.Close()

	key := generator.RandomString(8)
	value := generator.RandomString(8)

	err := client.Set(key, value, 0)
	if err != nil {
		return err
	}

	val, err := client.Get(key)
	if err != nil {
		return err
	}

	if val != value {
		return errors.New("redis test values did not match")
	}

	err = client.Del(key)
	if err != nil {
		return err
	}
	return nil
}

// Set a value in Redis
func (r *RedisClient) Set(key string, value string, expirationInHours int) error {
	expirationToDuration := time.Duration(expirationInHours) * time.Hour

	// If expiration is 0, set the key without expiration
	if expirationInHours == 0 {
		return r.client.Set(key, value, 0).Err()
	}
	return r.client.Set(key, value, expirationToDuration).Err()
}

// Set a value in Redis with a time.Duration instead of int
func (r *RedisClient) SetT(key string, value string, expiration time.Duration) error {
	return r.client.Set(key, value, expiration).Err()
}

// Get a value from Redis
func (r *RedisClient) Get(key string) (string, error) {
	return r.client.Get(key).Result()
}

// Delete a key from Redis
func (r *RedisClient) Del(key string) error {
	return r.client.Del(key).Err()
}

// Set a value in Redis with encryption
func (r *RedisClient) ESet(key string, value string, expirationInHours int) error {
	redisEncryptionKey := r.config.Encryption.Key
	if redisEncryptionKey == nil {
		return errors.New("redis encryption key variable is empty")
	}

	valueBytes := []byte(value)
	encValue, err := encryption.Encrypt(valueBytes, redisEncryptionKey, false)
	if err != nil {
		return err
	}
	expirationToDuration := time.Duration(expirationInHours) * time.Hour
	return r.client.Set(key, encValue, expirationToDuration).Err()
}

// Set a value in Redis with encryption and a time.Duration instead of int
func (r *RedisClient) ESetT(key string, value string, expiration time.Duration) error {
	redisEncryptionKey := r.config.Encryption.Key
	if redisEncryptionKey == nil {
		return errors.New("redis encryption key variable is empty")
	}

	valueBytes := []byte(value)
	encValue, err := encryption.Encrypt(valueBytes, redisEncryptionKey, false)
	if err != nil {
		return err
	}
	return r.client.Set(key, encValue, expiration).Err()
}

// Get a value from Redis with encryption
func (r *RedisClient) EGet(key string) (string, error) {
	redisEncryptionKey := r.config.Encryption.Key
	if redisEncryptionKey == nil {
		return "", errors.New("redis encryption key variable is empty")
	}

	encValue, err := r.client.Get(key).Result()
	if err != nil {
		return "", err
	}

	value, err := encryption.Decrypt(encValue, redisEncryptionKey, false)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

// Keys returns all keys based on a pattern
func (r *RedisClient) Keys(pattern string) ([]string, error) {
	return r.client.Keys(pattern).Result()
}

// Exists checks if a key exists
func (r *RedisClient) Exists(key string) (bool, error) {
	exists, err := r.client.Exists(key).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

// LPush pushes a value to the left of a list returning an err if it fails
func (r *RedisClient) LPush(key string, value string) error {
	response := r.client.LPush(key, value)
	if response.Err() != nil {
		return response.Err()
	}
	return nil
}

// RPop pops a value from the right of a list returning the value and an err if it fails
func (r *RedisClient) RPop(key string) (string, error) {
	response := r.client.RPop(key)
	if response.Err() != nil {
		return "", response.Err()
	}
	return response.Val(), nil
}

// BRPop pops a value from the right of a list blocking for a specified duration
//
// Note: This will only return the very rightmost value in the list, not all values
func (r *RedisClient) BRPop(key string, timeout time.Duration) (string, error) {
	response := r.client.BRPop(timeout, key)
	if response.Err() != nil {
		return "", response.Err()
	}
	if len(response.Val()) < 2 {
		return "", errors.New("BRPop response must include both the key and the value, but the response was shorter than expected")
	}
	return response.Val()[1], nil
}

// LLen returns the length of a list
func (r *RedisClient) LLen(key string) (int64, error) {
	response := r.client.LLen(key)
	if response.Err() != nil {
		return 0, response.Err()
	}
	return response.Val(), nil
}

// For backwards compatibility, these functions create a temporary client

// Set a value in Redis (legacy function)
// DEPRECATED: Use the RedisClient methods directly instead
func Set(key string, value string, expirationInHours int, redisConfig RedisConfiguration) error {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.Set(key, value, expirationInHours)
}

// Get a value from Redis (legacy function)
//
//	DEPRECATED: Use the RedisClient methods directly instead
func Get(key string, redisConfig RedisConfiguration) (string, error) {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.Get(key)
}

// Delete a key from Redis (legacy function)
// DEPRECATED: Use the RedisClient methods directly instead
func Del(key string, redisConfig RedisConfiguration) error {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.Del(key)
}

// Set a value in Redis with encryption (legacy function)
//
//	DEPRECATED: Use the RedisClient methods directly instead
func ESet(key string, value string, expirationInHours int, redisConfig RedisConfiguration) error {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.ESet(key, value, expirationInHours)
}

// Get a value from Redis with encryption (legacy function)
//
//	DEPRECATED: Use the RedisClient methods directly instead
func EGet(key string, redisConfig RedisConfiguration) (string, error) {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.EGet(key)
}

// Keys returns all keys based on a pattern (legacy function)
//
//	DEPRECATED: Use the RedisClient methods directly instead
func Keys(pattern string, redisConfig RedisConfiguration) ([]string, error) {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.Keys(pattern)
}

// Exists checks if a key exists (legacy function)
//
//	DEPRECATED: Use the RedisClient methods directly instead
func Exists(key string, redisConfig RedisConfiguration) (bool, error) {
	client := NewRedisClient(redisConfig)
	defer client.Close()
	return client.Exists(key)
}
