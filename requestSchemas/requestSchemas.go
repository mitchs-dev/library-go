/*
This package provides a standardized approach to handling request schemas
*/
package requestSchemas

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Struct to which the request schema configuration files should follow
type Schema struct {
	RequestSchema struct {
		SchemaVersion string `yaml:"schemaVersion"`
		Categories    []struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			Actions     []struct {
				Name               string   `yaml:"name"`
				Body               bool     `yaml:"body"`
				Method             string   `yaml:"method"`
				Description        string   `yaml:"description"`
				Parameters         []string `yaml:"parameters"`
				OptionalParameters []string `yaml:"optionalParameters"`
				Roles              []string `yaml:"roles"`
			} `yaml:"actions"`
		} `yaml:"categories"`
	} `yaml:"requestSchema"`
}

// GetSchema unmarshals the request schema data and returns a Schema struct
func (schema *Schema) GetSchema(requestSchemaData []byte) *Schema {
	if len(requestSchemaData) == 0 {
		log.Error("Request schema data is empty")
		return nil
	}
	err := yaml.Unmarshal(requestSchemaData, schema)
	if err != nil {
		log.Error("Error unmarshalling request schema file: ", err)
		return nil
	}
	return schema
}
