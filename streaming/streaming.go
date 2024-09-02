// packageName: streaming

/*
Package streaming provides functions for encoding and decoding base64 strings.
*/
package streaming

import (
	"encoding/base64"
	"strings"
)

// Encode a string to base64
func Encode(str string) string {
	return strings.TrimSpace(base64.StdEncoding.EncodeToString([]byte(str)))
}

// Decode a base64 string
func Decode(str string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(decoded)), nil
}

func EncodeFromByte(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeToByte(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}
