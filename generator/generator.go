package generator

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"
)

// Generate random string of length n
func RandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Generate a correlation ID with timestamp and random string
func CorrelationID(timeZone string) string {
	return StringTimestamp(timeZone) + RandomString(20)
}

// Generate timestamp in RFC3339 (minus dashes and colons) format with timezone provided
func StringTimestamp(timeZone string) string {
	loc := GetLocation(timeZone)
	timestamp := time.Now().In(loc).Format("20060102T150405Z0700")
	return strings.TrimSpace(timestamp)
}

// Generate timestamp in RFC3339 (minus colons and plus sign) format with timezone provided
func FileNameTimestamp(timeZone string) string {
	loc := GetLocation(timeZone)
	timestamp := time.Now().In(loc).Format("2006-01-02_15-04-05Z07:00")
	return strings.TrimSpace(timestamp)
}

// Generate timestamp in RFC3339 format with timezone provided
func Timestamp(timeZone string) string {
	loc := GetLocation(timeZone)
	return time.Now().In(loc).Format(time.RFC3339)
}

// Returns timestamp as epoch time in int format
func EpochTimestamp(timeZone string) int {
	loc := GetLocation(timeZone)
	return int(time.Now().In(loc).Unix())
}

// Returns the timezone location based on the timezone string provided
func GetLocation(timeZone string) *time.Location {
	var location string
	if timeZone == "" {
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
