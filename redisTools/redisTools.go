// Package name: badger

/*
	Package redisTools provides a wrapper functions for Redis database interactions.

REQUIRED VARIABLES: (SET ON INIT)

	RedisEncryptionKey string (If using encryption)

	RedisApplicationConfiguration struct {
		Addr     string `json:"address"`
		Password string `json:"password"`
		DB       int    `json:"db"`
	}
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
	Addr     string `json:"address"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// RedisEncryptionKey string for Redis encryption key
var RedisEncryptionKey string

// RedisApplicationConfiguration RedisConfiguration for Redis application configuration
var RedisApplicationConfiguration RedisConfiguration

// RedisOptions returns a new Redis options struct
func RedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     RedisApplicationConfiguration.Addr,
		Password: RedisApplicationConfiguration.Password,
		DB:       RedisApplicationConfiguration.DB,
	}
}

// TestConnection tests the connection to Redis
func TestConnection() error {
	rCon := redis.NewClient(RedisOptions())
	_, err := rCon.Ping().Result()
	if err != nil {
		return err
	}
	return nil
}

// TestAccess tests the access to Redis
func TestAccess() error {
	key := generator.RandomString(8)
	value := generator.RandomString(8)
	err := Set(key, value, 0)
	if err != nil {
		return err
	}
	val, err := Get(key)
	if err != nil {
		return err
	}
	if val != value {
		return errors.New("redis test values did not match")
	}
	err = Del(key)
	if err != nil {
		return err
	}
	return nil
}

// Set a value in Redis
func Set(key string, value string, expiration int) error {
	rCon := redis.NewClient(RedisOptions())
	err := rCon.Set(key, value, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

// Get a value from Redis
func Get(key string) (string, error) {
	rCon := redis.NewClient(RedisOptions())
	val, err := rCon.Get(key).Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

// Delete a key from Redis
func Del(key string) error {
	rCon := redis.NewClient(RedisOptions())
	err := rCon.Del(key).Err()
	if err != nil {
		return err
	}
	return nil
}

// Set a value in Redis with encryption
func ESet(key string, value string, expiration int) error {
	if RedisEncryptionKey == "" {
		return errors.New("redis encryption key variable is empty")
	}
	rCon := redis.NewClient(RedisOptions())
	encValue, err := encryption.Encrypt(value, RedisEncryptionKey)
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
func EGet(key string) (string, error) {
	if RedisEncryptionKey == "" {
		return "", errors.New("redis encryption key variable is empty")
	}
	rCon := redis.NewClient(RedisOptions())
	encValue, err := rCon.Get(key).Result()
	if err != nil {
		return "", err
	}
	value, err := encryption.Decrypt(encValue, RedisEncryptionKey)
	if err != nil {
		return "", err
	}
	return value, nil
}

// Keys returns all keys based on a pattern
func Keys(pattern string) ([]string, error) {
	rCon := redis.NewClient(RedisOptions())
	keys, err := rCon.Keys(pattern).Result()
	if err != nil {
		return nil, err
	}
	return keys, nil
}
