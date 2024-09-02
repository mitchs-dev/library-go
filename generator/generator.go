// packageName: generator

/*
Package generator provides functions to generate things, such as: random strings, timestamps, and correlation IDs, etc
*/
package generator

import (
	"math/rand"
	"strings"
	"time"
)

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

// Generate random string of length n
func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[seededRand.Intn(len(letters))]
	}
	return string(b)
}

// Generate a correlation ID with timestamp and random string
func CorrelationID(timeZone string) string {
	return StringTimestamp(timeZone) + RandomString(7)
}

// Generate timestamp in RFC3339 (minues dashes and colons) format with timezone provided
func StringTimestamp(timeZone string) string {
	timestamp := time.Now().In(GetLocation(timeZone)).Format(time.RFC3339)
	timestamp = strings.Replace(timestamp, "-", "", -1)
	timestamp = strings.Replace(timestamp, ":", "", -1)
	return strings.TrimSpace(timestamp)

}

// Generate timestamp in RFC3339 (minues dashes and colons) format with timezone provided
func FileNameTimestamp(timeZone string) string {
	timestamp := time.Now().In(GetLocation(timeZone)).Format(time.RFC3339)
	timestamp = strings.Replace(timestamp, ":", "-", -1)
	timestamp = strings.Replace(timestamp, "+", "_", -1)
	timestamp = strings.Replace(timestamp, "T", "_", -1)
	return strings.TrimSpace(timestamp)

}

// Generate timestamp in RFC3339 format with timezone provided
func Timestamp(timeZone string) string {
	return time.Now().In(GetLocation(timeZone)).Format(time.RFC3339)
}

// Returns timestamp as epoch time in int format
func EpochTimestamp(timeZone string) int {
	return int(time.Now().In(GetLocation(timeZone)).Unix())
}

// Returns the timezone location based on the timezone string provided
func GetLocation(timeZone string) *time.Location {
	var location string
	if timeZone == "" {
		// Set default timezone to UTC
		location = "UTC"
	} else {
		location = timeZone
	}
	setTimeZone, err := time.LoadLocation(location)
	if err != nil {
		setTimeZone, _ := time.LoadLocation("UTC")
		return setTimeZone

	}
	return setTimeZone
}
