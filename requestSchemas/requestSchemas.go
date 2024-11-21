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
		SchemaVersion string `yaml:"schemaVersion,omitempty" json:"schemaVersion,omitempty"`
		Categories    []struct {
			Name        string `yaml:"name,omitempty" json:"name,omitempty"`
			Description string `yaml:"description,omitempty" json:"description,omitempty"`
			Actions     []struct {
				Name               string   `yaml:"name,omitempty" json:"name,omitempty"`
				Body               bool     `yaml:"body,omitempty" json:"body,omitempty"`
				Method             string   `yaml:"method,omitempty" json:"method,omitempty"`
				Description        string   `yaml:"description,omitempty" json:"description,omitempty"`
				Parameters         []string `yaml:"parameters,omitempty" json:"parameters,omitempty"`
				OptionalParameters []string `yaml:"optionalParameters,omitempty" json:"optionalParameters,omitempty"`
				Headers            struct {
					Request  []HeaderEntry `yaml:"request,omitempty" json:"request,omitempty"`
					Response []HeaderEntry `yaml:"response,omitempty" json:"response,omitempty"`
				} `yaml:"headers"`
				Roles []string `yaml:"roles,omitempty" json:"roles,omitempty"`
			} `yaml:"actions,omitempty" json:"actions,omitempty"`
		} `yaml:"categories,omitempty" json:"categories,omitempty"`
	} `yaml:"requestSchema,omitempty" json:"requestSchema,omitempty"`
}

type HeaderEntry struct {
	Name        string `yaml:"name,omitempty" json:"name,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
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
