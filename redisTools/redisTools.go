// Package name: redisTools

/*
Package redisTools provides a wrapper functions for Redis database interactions.
*/
package redisTools

import (
	"errors"

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
	Key string
	IV  []byte
}

type RedisConfigHost struct {
	Addr     string
	Password string
	DB       int
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
	rCon := redis.NewClient(RedisOptions(redisConfig))
	_, err := rCon.Ping().Result()
	if err != nil {
		return err
	}
	return nil
}

// TestAccess tests the access to Redis
func TestAccess(redisConfig RedisConfiguration) error {

	key := generator.RandomString(8)
	value := generator.RandomString(8)
	err := Set(key, value, 0, redisConfig)
	if err != nil {
		return err
	}
	val, err := Get(key, redisConfig)
	if err != nil {
		return err
	}
	if val != value {
		return errors.New("redis test values did not match")
	}
	err = Del(key, redisConfig)
	if err != nil {
		return err
	}
	return nil
}

// Set a value in Redis
func Set(key string, value string, expiration int, redisConfig RedisConfiguration) error {

	rCon := redis.NewClient(RedisOptions(redisConfig))
	err := rCon.Set(key, value, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// Get a value from Redis
func Get(key string, redisConfig RedisConfiguration) (string, error) {

	rCon := redis.NewClient(RedisOptions(redisConfig))
	val, err := rCon.Get(key).Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

// Delete a key from Redis
func Del(key string, redisConfig RedisConfiguration) error {

	rCon := redis.NewClient(RedisOptions(redisConfig))
	err := rCon.Del(key).Err()
	if err != nil {
		return err
	}
	return nil
}

// Set a value in Redis with encryption
func ESet(key string, value string, expiration int, redisConfig RedisConfiguration) error {

	redisEncryptionKey := redisConfig.Encryption.Key
	redisEncryptionIV := redisConfig.Encryption.IV
	if redisEncryptionKey == "" {
		return errors.New("redis encryption key variable is empty")
	}
	if len(redisEncryptionIV) == 0 {
		return errors.New("redis encryption IV variable is empty")
	}
	rCon := redis.NewClient(RedisOptions(redisConfig))
	encValue, err := encryption.Encrypt(value, redisEncryptionKey, redisEncryptionIV)
	if err != nil {
		return err
	}
	err = rCon.Set(key, encValue, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// Get a value from Redis with encryption
func EGet(key string, redisConfig RedisConfiguration) (string, error) {

	redisEncryptionKey := redisConfig.Encryption.Key
	if redisEncryptionKey == "" {
		return "", errors.New("redis encryption key variable is empty")
	}
	rCon := redis.NewClient(RedisOptions(redisConfig))
	encValue, err := rCon.Get(key).Result()
	if err != nil {
		return "", err
	}
	value, err := encryption.Decrypt(encValue, redisEncryptionKey)
	if err != nil {
		return "", err
	}
	return value, nil
}

// Keys returns all keys based on a pattern
func Keys(pattern string, redisConfig RedisConfiguration) ([]string, error) {

	rCon := redis.NewClient(RedisOptions(redisConfig))
	keys, err := rCon.Keys(pattern).Result()
	if err != nil {
		return nil, err
	}
	return keys, nil
}
