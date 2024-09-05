/*
Provides generic templates for various projects
*/
package generic

// Version struct to hold version information
type Version struct {
	Symantic          string   `json:"symantic"`
	Hash              string   `json:"hash"`
	CompatibleConfigs []string `json:"compatible-configs"`
}
