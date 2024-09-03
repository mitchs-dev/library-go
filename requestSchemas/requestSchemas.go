package requestSchemas

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Schema struct {
	SchemaVersion string `yaml:"schemaVersion"`
	SchemaName    string `yaml:"schemaName"`
	Enabled       bool   `yaml:"enabled"`
	Actions       []struct {
		Name            string `yaml:"name"`
		Description     string `yaml:"description"`
		Enabled         bool   `yaml:"enabled"`
		Type            string `yaml:"type"`
		TargetComponent string `yaml:"targetComponent"`
		MinimumRole     string `yaml:"minimumRole"`
		Parameters      struct {
			Required []struct {
				Name          string `yaml:"name"`
				Description   string `yaml:"description"`
				ParameterType string `yaml:"parameterType"`
				DefaultValue  string `yaml:"defaultValue"`
			} `yaml:"required"`
			Optional []struct {
				Name          string `yaml:"name"`
				Description   string `yaml:"description"`
				ParameterType string `yaml:"parameterType"`
				DefaultValue  string `yaml:"defaultValue"`
			} `yaml:"optional"`
		} `yaml:"parameters"`
	} `yaml:"actions"`
}

func (schema *Schema) GetSchema(requestSchemaPath string) *Schema {
	schemaData, err := os.ReadFile(requestSchemaPath)
	if err != nil {
		log.Error("Error reading request schema file: ", err)
		return nil
	}
	err = yaml.Unmarshal(schemaData, schema)
	if err != nil {
		log.Error("Error unmarshalling request schema file: ", err)
		return nil
	}
	return schema
}
