// packageName: webhook

/*
This package provides an interface to create, delete, and process webhook payloads.
*/
package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/mitchs-dev/library-go/generator"
	"github.com/mitchs-dev/library-go/hmac"
	"github.com/mitchs-dev/library-go/redisTools"
	log "github.com/sirupsen/logrus"
)

/*
	Create creates a new webhook and returns the webhook ID, the (provided as input) webhook name, and webhook secret.

If you choose to not store the webhook in Redis, you will need to manage the webhook information yourself.

Note: webhookName is a string that identifies the webhook and should be unique

Note: requireSecret is a boolean that determines if a secret is required for the webhook and will be generated if true

Note: to use storeInRedis, you must have Redis configured. See the redisTools package for additional details on this

Note: timeZone can be any valid timezone string (e.g. "America/New_York")
*/
func Create(webhookName string, requireSecret bool, storeInRedis bool, timeZone string, redisConfig redisTools.RedisConfiguration) (string, string, string, error) {

	// Before creating a webhook, let's
	// 1. Verify that the webhook name is not empty
	// 2. Verify that the webhook name does not already exist
	if webhookName == "" {
		return "", "", "", errors.New("webhook name cannot be empty")
	}
	webhookIDs, webhookNames, _, err := List(redisConfig)
	if err != nil {
		return "", "", "", err
	}
	for i := 0; i < len(webhookNames); i++ {
		if webhookNames[i] == webhookName {
			return "", "", "", errors.New("webhook name already exists (" + webhookIDs[i] + ") - Webhook names must be unique")
		}
	}

	log.Debug("Creating webhook with name: ", webhookName)

	// All webhooks are identified by a unique webhook ID (a random string with a timestamp appended)
	webhookID := generator.RandomString(16) + "." + fmt.Sprint(generator.EpochTimestamp(timeZone))

	log.Debug("Webhook ID (" + webhookID + ") assigned to webhook: " + webhookName)

	// Generate a secret if required
	var webhookSecret string
	if requireSecret {
		log.Debug("Generating secret for webhook: " + webhookID)
		webhookSecret = generator.RandomString(32)
	} else {
		log.Debug("No secret required for webhook: " + webhookID)
		webhookSecret = ""
	}

	// Store the webhook in Redis if required
	if !storeInRedis {
		log.Debug("Webhook (" + webhookID + ") will not be stored in Redis - Returning webhook ID, name, and secret")
		return webhookID, webhookName, webhookSecret, nil
	} else {

		// Verify that Redis is configured
		err := redisVerification(redisConfig)
		if err != nil {
			return "", "", "", err
		}

		log.Debug("Redis is configured - Storing webhook (" + webhookID + ") in Redis")

		// Once we have verified that Redis is configured, we can store the webhook in Redis
		// As this information should be considered sensitive, we will use the encryption methods defined in the redisTools package (ESet, EGet, etc)
		// We will store the webhook ID as the key and the webhook name and secret as the value
		webhookRedisKey := "SYSTEM.WEBHOOK." + webhookID

		err = redisTools.ESet(webhookRedisKey+".SECRET", webhookSecret, 0, redisConfig)
		if err != nil {
			return "", "", "", err
		}
		err = redisTools.ESet(webhookRedisKey+".NAME", webhookName, 0, redisConfig)
		if err != nil {
			return "", "", "", err
		}

		log.Debug("Webhook (" + webhookID + ") stored in Redis")

		// If everything is successful, return the webhook ID, name, and secret
		return webhookID, webhookName, webhookSecret, nil
	}
}

/*
	Delete deletes a webhook by webhook ID or webhook name

Note: You can provide the webhook ID or webhook name, or both; It will match on either (First match wins)

Note: It is advised to provide the webhook ID over the webhook name for accuracy and performance
*/
func Delete(webhookID string, webhookName string, redisConfig redisTools.RedisConfiguration) error {

	if webhookID == "" && webhookName == "" {
		return errors.New("webhook ID or webhook name is required")
	}

	log.Debug("Deleting webhook using provided (if applicable) ID: ", webhookID, " and (if applicable) name: ", webhookName)

	// Verify that Redis is configured
	err := redisVerification(redisConfig)
	if err != nil {
		return err
	}

	log.Debug("Redis is configured - Deleting webhook with ID: ", webhookID, " and name: ", webhookName)

	// Get all keys from Redis
	keys, err := redisTools.Keys("SYSTEM.WEBHOOK.*.NAME", redisConfig)
	if err != nil {
		return err
	}

	// If there are no keys, return an empty list
	if len(keys) == 0 {
		return errors.New("no webhooks found")
	}

	var webhookIDForDeletion string

	// If there are keys, get the values
	for _, key := range keys {

		// For the webhook ID, we will remove the "SYSTEM.WEBHOOK." prefix
		webhookIDFromRedis := key[len("SYSTEM.WEBHOOK."):]

		// We will also want to remove the ".NAME" suffix
		webhookIDFromRedis = strings.Replace(webhookIDFromRedis, ".NAME", "", 1)

		// We want to make sure it's also removed from the key
		key = strings.Replace(key, ".NAME", "", 1)

		// If we match on the webhook ID, set the foundWebhookID flag
		if webhookIDFromRedis == webhookID {
			webhookIDForDeletion = webhookID
			break
		}

		// Get the webhook name and secret
		webhookNameFromRedis, err := redisTools.EGet(key+".NAME", redisConfig)
		if err != nil {
			return err
		}

		if webhookNameFromRedis == webhookName {
			log.Debug("Webhook name (" + webhookName + ") matched with ID: " + webhookIDFromRedis)
			webhookIDForDeletion = webhookIDFromRedis
			break
		}
	}

	// The for loop sets the webhookIDForDeletion to the first match
	// If webhookIDForDeletion is still empty, we did not find a match
	if webhookIDForDeletion == "" {
		return errors.New("webhook not found")
	}

	log.Debug("Webhook found for deletion: ", webhookIDForDeletion)

	// If we found a match, delete the webhook from Redis
	err = redisTools.Del("SYSTEM.WEBHOOK."+webhookIDForDeletion+".NAME", redisConfig)
	if err != nil {
		return err
	}
	err = redisTools.Del("SYSTEM.WEBHOOK."+webhookIDForDeletion+".SECRET", redisConfig)
	if err != nil {
		return err
	}

	log.Debug("Webhook deleted: ", webhookIDForDeletion)

	return nil
}

/*
	List returns a list of all webhook IDs, names and keys stored in Redis

Note: If you did not store the webhooks in Redis initially, this function will return an empty list
*/
func List(redisConfig redisTools.RedisConfiguration) ([]string, []string, []string, error) {

	// Verify that Redis is configured
	err := redisVerification(redisConfig)
	if err != nil {
		log.Error("Error verifying Redis configuration")
		return nil, nil, nil, err
	}

	log.Debug("Redis is configured - Getting list of webhooks")

	// Get all keys from Redis (by name)
	keys, err := redisTools.Keys("SYSTEM.WEBHOOK.*.NAME", redisConfig)
	if err != nil {
		log.Error("Error fetching keys from Redis")
		return nil, nil, nil, err
	}

	log.Debug("Found ", len(keys), " webhook(s)")

	// If there are no keys, return an empty list
	if len(keys) == 0 {
		log.Debug("No webhooks found")
		return []string{}, []string{}, []string{}, nil
	}

	// If there are keys, get the values
	var webhookIDs []string
	var webhookNames []string
	var webhookKeys []string
	for _, key := range keys {
		// For the webhook ID, we will remove the "SYSTEM.WEBHOOK." prefix
		webhookID := key[len("SYSTEM.WEBHOOK."):]

		// We will also want to remove the ".NAME" suffix
		webhookID = strings.Replace(webhookID, ".NAME", "", 1)

		// We want to make sure it's also removed from the key
		key = strings.Replace(key, ".NAME", "", 1)

		log.Debug("Processing webhook: " + webhookID + " to add to list")

		// Get the webhook name and secret
		webhookName, err := redisTools.EGet(key+".NAME", redisConfig)
		if err != nil {
			log.Error("Error fetching name for webhook: ", webhookID)
			return nil, nil, nil, err
		}
		webhookSecret, err := redisTools.EGet(key+".SECRET", redisConfig)
		if err != nil {
			log.Error("Error fetching secret for webhook: ", webhookID)
			return nil, nil, nil, err
		}

		// Create our lists
		webhookIDs = append(webhookIDs, webhookID)
		webhookNames = append(webhookNames, webhookName)
		webhookKeys = append(webhookKeys, webhookSecret)
	}

	log.Debug("Returning list of webhooks")

	// Return the list of webhooks
	return webhookIDs, webhookNames, webhookKeys, nil
}

var GHPS GitHubPayloadStruct

/*
GetGitHubPayload simply returns the GitHubPayloadStruct given a file path
*/
func (payloadItem *GitHubPayloadStruct) GetGitHubPayload(payloadFilePath string) *GitHubPayloadStruct {

	// Read the file
	jsonFile, err := os.ReadFile(payloadFilePath)
	if err != nil {
		log.Error("Error opening GitHub Payload file ("+payloadFilePath+"): ", err)
		return nil
	}

	// Unmarshal the payload body into the GitHubPayloadStruct
	err = json.Unmarshal(jsonFile, &payloadItem)
	if err != nil {
		log.Error("Error unmarshalling GitHub Payload file ("+payloadFilePath+"): ", err)
		return nil
	}

	log.Debug("GitHub Payload file (" + payloadFilePath + ") was successfully unmarshalled and is ready for processing")
	return payloadItem
}

/*
GitHubPayload is a function which processes a GitHub webhook payload and returns the payload as a GitHubPayloadStruct
*/
func (payloadItem *GitHubPayloadStruct) GitHubPayload(w http.ResponseWriter, r *http.Request, redisConfig redisTools.RedisConfiguration) *GitHubPayloadStruct {

	// Ensure that the webhookName is set as a parameter
	webhookName := r.URL.Query().Get("webhookName")
	if webhookName == "" {
		http.Error(w, "Webhook name is required", http.StatusBadRequest)
		return nil
	}

	// Ensure we have the correct headers
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return nil
	}
	if r.Header.Get("X-GitHub-Event") == "" {
		http.Error(w, "Invalid X-GitHub-Event", http.StatusBadRequest)
		return nil
	}
	if r.Header.Get("X-GitHub-Hook-ID") == "" {
		http.Error(w, "Invalid X-GitHub-Hook-ID", http.StatusBadRequest)
		return nil
	}
	if r.Header.Get("X-GitHub-Delivery") == "" {
		http.Error(w, "Invalid X-GitHub-Delivery", http.StatusBadRequest)
		return nil
	}
	GitHubDeliveryID := r.Header.Get("X-GitHub-Delivery")
	if r.Header.Get("X-Hub-Signature") == "" {
		http.Error(w, "No X-Hub-Signature", http.StatusBadRequest)
		return nil
	}
	if r.Header.Get("X-Hub-Signature-256") == "" {
		http.Error(w, "No X-Hub-Signature-256", http.StatusBadRequest)
		return nil
	}
	GitHubPayloadSignature256 := r.Header.Get("X-Hub-Signature-256")

	// Verify the body is not empty
	if r.Body == nil {
		http.Error(w, "Empty body", http.StatusBadRequest)
		return nil
	}

	// Write body to "bodyBytes"
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return nil
	}

	log.Debug("Processing GitHub payload with delivery ID: ", GitHubDeliveryID+" (Hook ID: "+r.Header.Get("X-GitHub-Hook-ID")+" | Event: ", r.Header.Get("X-GitHub-Event")+")")

	// Fetch webhook ID and secret from Redis
	webhookIDs, webhookNames, webhookSecrets, err := List(redisConfig)
	if err != nil {
		http.Error(w, "Error fetching webhooks", http.StatusInternalServerError)
		return nil
	}

	var webhookID string
	var webhookSecret string

	// Find the webhook ID and secret
	for i := 0; i < len(webhookNames); i++ {
		if webhookNames[i] == webhookName {
			webhookID = webhookIDs[i]
			webhookSecret = webhookSecrets[i]
			break
		}
	}

	// If we did not find the webhook, return an error
	if webhookID == "" {
		http.Error(w, "Webhook not found", http.StatusNotFound)
		return nil
	}

	// Right now only push events are supported
	if r.Header.Get("X-GitHub-Event") != "push" {
		http.Error(w, "Push event is the only supported event", http.StatusBadRequest)
		return nil
	}

	// Verify the payload signature
	err = hmac.Validate(bodyBytes, GitHubPayloadSignature256, webhookSecret)
	if err != nil {
		http.Error(w, "Invalid payload signature", http.StatusUnauthorized)
		return nil
	}

	log.Debug("Payload signature verified for delivery ID: ", GitHubDeliveryID)

	// Get the payload body

	bodyToString := string(bodyBytes)

	// Unmarshal the payload body into the GitHubPayloadStruct
	err = json.Unmarshal([]byte(bodyToString), &GHPS)
	if err != nil {
		http.Error(w, "Error unmarshalling payload", http.StatusInternalServerError)
		return nil
	}

	log.Debug("GitHub Payload (Delivery ID: ", GitHubDeliveryID, "):  was successfully unmarshalled and is ready for processing")

	// Return the GitHubPayloadStruct
	log.Debug("Returning GitHub payload for delivery ID: ", GitHubDeliveryID)
	return &GHPS

}

// Matches webhook name and ID
func MatchID(webhookName string, webhookID string, redisConfig redisTools.RedisConfiguration) (bool, error) {

	// Immediately return an error if webhookName and webhookID are empty
	if webhookName == "" || webhookID == "" {
		return false, errors.New("webhook name and ID are required")
	}

	err := redisVerification(redisConfig)
	if err != nil {
		return false, err
	}

	log.Debug("Matching webhook name: ", webhookName, " and ID: ", webhookID)

	keys, err := redisTools.Keys("SYSTEM.WEBHOOK.*.NAME", redisConfig)
	if err != nil {
		return false, err
	}

	if len(keys) == 0 {
		return false, errors.New("no webhooks found")
	}

	for _, key := range keys {

		// For the webhook ID, we will remove the "SYSTEM.WEBHOOK." prefix
		webhookIDFromRedis := key[len("SYSTEM.WEBHOOK."):]

		// We will also want to remove the ".NAME" suffix
		webhookIDFromRedis = strings.Replace(webhookIDFromRedis, ".NAME", "", 1)

		// We want to make sure it's also removed from the key
		key = strings.Replace(key, ".NAME", "", 1)

		// Get the webhook name and secret
		webhookNameFromRedis, err := redisTools.EGet(key+".NAME", redisConfig)
		if err != nil {
			return false, err
		}

		if webhookNameFromRedis == webhookName && webhookIDFromRedis == webhookID {
			log.Debug("Webhook name (" + webhookName + ") and ID (" + webhookID + ") matched")
			return true, nil
		}
	}

	// If we did not find a match, return false, but no error
	// As this is not an error condition but a logical condition
	log.Debug("Webhook name (" + webhookName + ") and ID (" + webhookID + ") did not match")
	return false, nil

}

// GetSecret returns the secret for a webhook by webhook ID or webhook name
func GetSecret(webhookID string, webhookName string, redisConfig redisTools.RedisConfiguration) (string, error) {

	if webhookID == "" && webhookName == "" {
		return "", errors.New("webhook ID or webhook name is required")
	}

	log.Debug("Getting secret using provided (if applicable) ID: ", webhookID, " and (if applicable) name: ", webhookName)

	err := redisVerification(redisConfig)
	if err != nil {
		return "", err
	}

	log.Debug("Redis is configured - Getting secret for webhook with ID: ", webhookID, " and name: ", webhookName)

	idArray, nameArray, secretArray, err := List(redisConfig)
	if err != nil {
		return "", err
	}

	if len(idArray) == 0 {
		return "", errors.New("no webhooks found")
	}

	for idIndex := 0; idIndex < len(idArray); idIndex++ {
		if idArray[idIndex] == webhookID {
			log.Debug("Webhook ID (" + webhookID + ") matched - Returning secret")
			return secretArray[idIndex], nil
		}
		if nameArray[idIndex] == webhookName {
			log.Debug("Webhook name (" + webhookName + ") matched - Returning secret")
			return secretArray[idIndex], nil
		}
	}

	return "", errors.New("webhook not found")

}

/*
Verifies that Redis is configured but does not run tests as this should be done in the main application initalization
*/
func redisVerification(redisConfig redisTools.RedisConfiguration) error {

	if redisConfig.Encryption.Key == nil {
		return errors.New("redis does not seem to be configured (Redis Encryption Key is empty)")
	}

	return nil
}
