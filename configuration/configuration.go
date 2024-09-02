/*
This package provides functions to interact with configuration files.
*/
package configuration

import (
	"reflect"

	log "github.com/sirupsen/logrus"
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
