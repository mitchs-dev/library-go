/*
This package provides functions to interact with configuration files.
*/
package configuration

import (
	"errors"
	"reflect"
	"strings"

	"github.com/mitchs-dev/build-struct/pkg/external"
	"github.com/mitchs-dev/library-go/streaming"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

/*
	MergeWithDefault merges a provided configuration with a provided default configuration.

If you have a user/app provided configuration that does not contain the full configuration,
you can use this function to merge the user/app provided configuration with the default configuration.
*/
func MergeWithDefault(defaultMap map[interface{}]interface{}, userMap map[interface{}]interface{}) map[interface{}]interface{} {
	// Loop through the default map
	for key, value := range defaultMap {
		// Check if the key exists in the user map
		if _, ok := userMap[key]; !ok {
			// If the key does not exist in the user map, add it
			userMap[key] = value
		} else {
			// If the key does exist in the user map, check if it is a map
			if _, ok := value.(map[interface{}]interface{}); ok {
				// If the key is a map, merge the maps
				userMap[key] = MergeWithDefault(value.(map[interface{}]interface{}), userMap[key].(map[interface{}]interface{}))
			}

			// Check that the user-provided value is of the same type as the default value
			if reflect.TypeOf(value) != reflect.TypeOf(userMap[key]) {
				// If the types are different, use the default value
				log.Warn("Configuration value for key ", key, " is of a different type (Have: "+reflect.TypeOf(userMap[key]).String()+" | Want: "+reflect.TypeOf(value).String()+") than the default value. Using default value: ", value)
				userMap[key] = value
			}

			// Check if the user-provided value is empty or nil, if so, use the default value
			if userMap[key] == nil || userMap[key] == "" {
				userMap[key] = value
			}

		}
	}
	return userMap
}

// YAMLInlineToConfig converts an array of strings to a usable YAML formatted []byte
func YAMLInlineToConfig(configStoreKeyList, configStoreKeyTypeList []string) ([]byte, error) {
	// Convert configStoreKeyList to a nested map
	configStoreKeyMap := make(map[string]interface{})
	seenKeys := make(map[string]bool)

	for keyIndex, key := range configStoreKeyList {
		// Check if key has been seen before
		if _, ok := seenKeys[key]; ok {
			continue
		}

		seenKeys[key] = true

		parts := strings.Split(key, ".")

		// Initialize a reference to the root of the map
		m := configStoreKeyMap

		// For each part in the key except the last one
		for _, part := range parts[:len(parts)-1] {
			// If the part is not already a key in the map, add it
			if _, ok := m[part]; !ok {
				m[part] = make(map[string]interface{})
			}

			// Update the reference to the map that is the value of the current part
			m = m[part].(map[string]interface{})
		}

		var value interface{}

		switch configStoreKeyTypeList[keyIndex] {
		case "string":
			value = ""
		case "bool":
			value = false
		case "int":
			value = 0
		case "float64":
			value = 0.0
		case "[]byte":
			value = streaming.EncodeFromByte([]byte("string"))
		default:
			value = ""

		}

		// Set the value of the last part in the key to the desired value
		m[parts[len(parts)-1]] = value
	}

	yamlData, err := yaml.Marshal(configStoreKeyMap)
	if err != nil {
		return nil, errors.New("error marshalling yaml data: " + err.Error())
	}

	return yamlData, nil

}

// YAMLInlineToMap converts an array of strings to a usable struct
func YAMLInlineToStruct(structName string, configStoreKeyList, configStoreKeyTypeList []string) (string, error) {

	yamlData, err := YAMLInlineToConfig(configStoreKeyList, configStoreKeyTypeList)
	if err != nil {
		return "", errors.New("error converting inline yaml to config: " + err.Error())
	}

	builtStruct, err := external.Call(structName, "", yamlData)
	if err != nil {
		return "", errors.New("error building struct: " + err.Error())
	}

	return builtStruct, nil
}

// GetValueForInlineYAML returns the value for a key in a nested map for the provided key
func GetValueForInlineYAML(key string, configData []byte, configStruct interface{}) (interface{}, string, error) {
	// Convert the configData to a nested map
	configStoreKeyMap := make(map[interface{}]interface{})
	err := yaml.Unmarshal(configData, &configStoreKeyMap)
	if err != nil {
		return nil, "", errors.New("error unmarshalling yaml data: " + err.Error())
	}

	// Split the key into parts
	parts := strings.Split(key, ".")

	// Initialize a reference to the root of the map
	m := configStoreKeyMap

	// For each part in the key except the last one
	for _, part := range parts[:len(parts)-1] {
		// If the part is not already a key in the map, return an error
		if _, ok := m[part]; !ok {
			return nil, "", errors.New("key not found: " + key)
		}

		// Update the reference to the map that is the value of the current part
		m = m[part].(map[interface{}]interface{})
	}

	if _, ok := m[parts[len(parts)-1]]; !ok {
		return nil, "", errors.New("key not found: " + key)
	}

	// Get the type of the value
	valueType := reflect.TypeOf(m[parts[len(parts)-1]]).String()

	// Return the value of the last part in the key
	return m[parts[len(parts)-1]], valueType, nil
}
