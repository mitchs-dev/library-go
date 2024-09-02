// packageName: templates/kubernetes

/*
This package is used for general Kubernetes templates such as kubeconfig files.
*/
package kubernetes

import (
	"github.com/mitchs-dev/library-go/processor"
	"github.com/mitchs-dev/library-go/streaming"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Kubeconfig struct {
	ApiVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Users          []struct {
		Name string `yaml:"name"`
		User struct {
			Token string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// Function used to generate a kubeconfig file from the Kubeconfig struct. `contextName` is used for the Kubeconfig's `.cluster[x].name`, `context[x].name` and `current-context`.  `userName` is used for `user[x].name`,.
func KubeConfigFile(contextName string, namespace string, encodedCertificateAuthorityData string, clusterServerURL string, userName string, encodedTokenData string) string {
	// Token must be decoded before it can be used in the kubeconfig file
	decodedToken, _ := streaming.Decode(encodedTokenData)
	config := `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ` + encodedCertificateAuthorityData + `
    server: ` + clusterServerURL + `
  name: ` + contextName + `
contexts:
- context:
    cluster: ` + contextName + `
    user: ` + userName + `
    namespace: ` + namespace + `
  name: ` + contextName + `
current-context: ` + contextName + `
users:
- name: ` + userName + `
  user:
    token: ` + decodedToken
	return config
}

// Use: GetKubeConfig |DESCRIPTION| Used to retrieve values from a kubeconfig file. **Use with the Kubeconfig struct.** |ARGS| clusterName (string), kubeConfigPath (string)
func (configItem *Kubeconfig) GetKubeConfig(clusterName string, kubeConfigPath string) *Kubeconfig {
	log.Debug("Getting kubernetes configuration file for cluster: ", clusterName)
	// Read the kubernetes configuration file from disk
	kubeConfigData := processor.ReadFile(kubeConfigPath)
	// Convert the kubernetes cluster config data to a byte array
	err := yaml.Unmarshal(kubeConfigData, configItem)
	if err != nil {
		log.Fatalf("Configuration Unmarshal: %v", err)
	}
	return configItem
}
