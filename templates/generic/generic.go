package generic

type Version struct {
	Symantic          string   `json:"symantic"`
	Hash              string   `json:"hash"`
	CompatibleConfigs []string `json:"compatible-configs"`
}
