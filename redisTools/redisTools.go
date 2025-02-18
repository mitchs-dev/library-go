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
	Encryption struct {
		Key string
		IV  []byte
	}
	Host struct {
		Addr     string
		Password string
		DB       int
	}
}

// redisApplicationConfiguration RedisConfiguration for Redis application configuration
var redisApplicationConfiguration RedisConfiguration

// RedisOptions returns a new Redis options struct
func RedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     redisApplicationConfiguration.Host.Addr,
		Password: redisApplicationConfiguration.Host.Password,
		DB:       redisApplicationConfiguration.Host.DB,
	}
}

// TestConnection tests the connection to Redis
func TestConnection(redisConfig RedisConfiguration) error {
	redisApplicationConfiguration = redisConfig
	rCon := redis.NewClient(RedisOptions())
	_, err := rCon.Ping().Result()
	if err != nil {
		return err
	}
	return nil
}

// TestAccess tests the access to Redis
func TestAccess(redisConfig RedisConfiguration) error {
	redisApplicationConfiguration = redisConfig
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
	redisApplicationConfiguration = redisConfig
	rCon := redis.NewClient(RedisOptions())
	err := rCon.Set(key, value, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// Get a value from Redis
func Get(key string, redisConfig RedisConfiguration) (string, error) {
	redisApplicationConfiguration = redisConfig
	rCon := redis.NewClient(RedisOptions())
	val, err := rCon.Get(key).Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

// Delete a key from Redis
func Del(key string, redisConfig RedisConfiguration) error {
	redisApplicationConfiguration = redisConfig
	rCon := redis.NewClient(RedisOptions())
	err := rCon.Del(key).Err()
	if err != nil {
		return err
	}
	return nil
}

// Set a value in Redis with encryption
func ESet(key string, value string, expiration int, redisConfiguration RedisConfiguration) error {
	redisApplicationConfiguration = redisConfiguration
	redisEncryptionKey := redisApplicationConfiguration.Encryption.Key
	redisEncryptionIV := redisApplicationConfiguration.Encryption.IV
	if redisEncryptionKey == "" {
		return errors.New("redis encryption key variable is empty")
	}
	if len(redisEncryptionIV) == 0 {
		return errors.New("redis encryption IV variable is empty")
	}
	rCon := redis.NewClient(RedisOptions())
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
func EGet(key string, redisConfiguration RedisConfiguration) (string, error) {
	redisApplicationConfiguration = redisConfiguration
	redisEncryptionKey := redisApplicationConfiguration.Encryption.Key
	if redisEncryptionKey == "" {
		return "", errors.New("redis encryption key variable is empty")
	}
	rCon := redis.NewClient(RedisOptions())
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
func Keys(pattern string, redisConfiguration RedisConfiguration) ([]string, error) {
	redisApplicationConfiguration = redisConfiguration
	rCon := redis.NewClient(RedisOptions())
	keys, err := rCon.Keys(pattern).Result()
	if err != nil {
		return nil, err
	}
	return keys, nil
}
