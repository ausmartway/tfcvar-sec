package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/TwinProduction/go-color"
	tfe "github.com/hashicorp/go-tfe"
)

var sensitiveTfcVariablePattens = []string{
	"token",
	"credential",
	"session",
	"keyfile",
	"secret",
	"certificate",
	"key",
	"cert",
	"password",
	"connection",
}

var sensitiveEnvVariables = map[string]bool{
	//aws
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN":     true,

	//gcp
	"GOOGLE_CREDENTIALS":             true,
	"GOOGLE_APPLICATION_CREDENTIALS": true,
	"GOOGLE_CLOUD_KEYFILE_JSON":      true,
	"GCLOUD_KEYFILE_JSON":            true,
	"GOOGLE_OAUTH_ACCESS_TOKEN":      true,

	//azure
	"ARM_CLIENT_SECRET":               true,
	"ARM_CLIENT_CERTIFICATE_PASSWORD": true,
	"ARM_CLIENT_CERTIFICATE":          true,

	//alicloud
	"ALICLOUD_SECRET_KEY":              true,
	"ALICLOUD_SECURITY_TOKEN":          true,
	"ALICLOUD_SHARED_CREDENTIALS_FILE": true,

	//TencetCloud
	"TENCENTCLOUD_SECRET_KEY":     true,
	"TENCENTCLOUD_SECURITY_TOKEN": true,

	//DigitalOcean
	"DIGITALOCEAN_ACCESS_TOKEN": true,
	"DIGITALOCEAN_TOKEN":        true,
	"SPACES_SECRET_ACCESS_KEY":  true,

	//general
	"TOKEN": true,

	//vault
	"VAULT_TOKEN": true,

	//terraform enterprise/cloud
	"TFE_TOKEN": true,

	//Consul
	"CONSUL_HTTP_TOKEN": true,
	"CONSUL_TOKEN":      true,

	//Nomad
	"NOMAD_HTTP_AUTH":   true,
	"NOMAD_CLIENT_CERT": true,
	"NOMAD_CLIENT_KEY":  true,
	"NOMAD_TOKEN":       true,

	//Boundary
	"BOUNDARY_TOKEN": true,

	//Hashicorp Cloud Platform
	"HCP_CLIENT_SECRET": true,

	//k8s
	"KUBE_PASSWORD":             true,
	"KUBE_TOKEN":                true,
	"KUBE_CLIENT_CERT_DATA":     true,
	"KUBE_CLIENT_KEY_DATA":      true,
	"KUBE_CLUSTER_CA_CERT_DATA": true,

	//Helm
	"HELM_DRIVER_SQL_CONNECTION_STRING": true,

	//vsphere
	"VSPHERE_PASSWORD": true,

	//vRA
	"vRA_ACCESS_TOKEN":  true,
	"vRA_REFRESH_TOKEN": true,

	//Microsoft Active Directory
	"AD_PASSWORD": true,

	//Aritfactory
	"ARITFACTORY_PASSWORD":     true,
	"ARTIFACTORY_ACCESS_TOKEN": true,
	"ARTIFACTORY_API_KEY":      true,

	//Azure DevOps
	"AZDO_PERSONAL_ACCESS_TOKEN": true,

	//Bigip F5
	"BIGIP_PASSWORD": true,

	//Cloudflare
	"CLOUDFLARE_API_KEY":              true,
	"CLOUDFLARE_API_TOKEN":            true,
	"CLOUDFLARE_API_USER_SERVICE_KEY": true,

	//Databricks
	"DATABRICKS_TOKEN":               true,
	"DATABRICKS_PASSWORD":            true,
	"DATABRICKS_AZURE_CLIENT_SECRET": true,

	//Datadog
	"DD_API_KEY": true,
	"DD_APP_KEY": true,

	//Gitlab
	"GITLAB_TOKEN": true,

	//Github
	"GITHUB_TOKEN":        true,
	"GITHUB_APP_PEM_FILE": true,

	//Grafana
	"GRAFANA_AUTH":            true,
	"GRAFANA_SM_ACCESS_TOKEN": true,
	"GRAFANA_TLS_KEY":         true,
	"GRAFANA_TLS_CER":         true,
	"GRAFANA_CLOUD_API_KEY":   true,

	//MongoDBAtlas
	"MONGODB_ATLAS_PRIVATE_KEY": true,

	//Newrelic
	"NEW_RELIC_API_KEY":             true,
	"NEW_RELIC_INSIGHTS_INSERT_KEY": true,
	"NEW_RELIC_API_CACERT":          true,

	//Rancher
	"RANCHER_ACCESS_KEY": true,
	"RANCHER_SECRET_KEY": true,
	"RANCHER_TOKEN_KEY":  true,

	//SignalFX
	"SFX_AUTH_TOKEN": true,

	//Splunk
	"SPLUNK_PASSWORD":   true,
	"SPLUNK_AUTH_TOKEN": true,

	//Sumologic
	"SUMOLOGIC_ACCESSKEY": true,

	//1Password
	"OP_CONNECT_TOKEN": true,
}

//flat structure
type varVialation struct {
	orgName       string
	workspaceName string
	category      string
	varName       string
}

var varVialations []varVialation

// //layered structure
// type category struct {
// 	name      string
// 	variables []string
// }
// type workspace struct {
// 	name string
// 	cat  []category
// }

// type org struct {
// 	name      string
// 	workspace workspace
// }

func newVarVialation(orgName string, workspaceName string, category string, varName string) *varVialation {
	p := varVialation{workspaceName: workspaceName}
	p.varName = varName
	p.category = category
	p.orgName = orgName
	return &p
}

func contains(str string, substrlist []string) bool {
	for _, substr := range substrlist {
		if strings.Contains(str, substr) {
			return true
		}
	}
	return false
}

func main() {

	const defaultHostname = "https://app.terraform.io"

	tfeHost := ""
	tfeToken := ""

	if os.Getenv("TFE_HOSTNAME") != "" {
		tfeHost = os.Getenv("TFE_HOSTNAME")
	} else {
		tfeHost = defaultHostname
	}

	if os.Getenv("TFE_TOKEN") != "" {
		tfeToken = os.Getenv("TFE_TOKEN")
	}

	config := &tfe.Config{
		Address: tfeHost,
		Token:   tfeToken,
	}

	client, err := tfe.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// Create a context
	ctx := context.Background()

	//get all orgs
	orgs, err := client.Organizations.List(ctx, tfe.OrganizationListOptions{})
	if err != nil {
		log.Fatal(err)
	} else {

		for _, org := range orgs.Items {
			//for each org, get all workspaces
			ws, err := client.Workspaces.List(ctx, org.Name, tfe.WorkspaceListOptions{})
			if err != nil {
				log.Fatal(err)
			} else {
				for _, workspaces := range ws.Items {
					//for each workspace, get all variables
					variables, _ := client.Variables.List(ctx, workspaces.ID, tfe.VariableListOptions{
						ListOptions: tfe.ListOptions{
							PageNumber: 1,
							PageSize:   1000,
						},
					})
					//for each variable, see if it is in the list but not marked sensitive
					for _, wsVar := range variables.Items {
						switch wsVar.Category {
						case "env":
							if sensitiveEnvVariables[wsVar.Key] && !wsVar.Sensitive {
								varVialations = append(varVialations, *newVarVialation(org.Name, workspaces.Name, string(wsVar.Category), wsVar.Key))
							} else if !wsVar.Sensitive && strings.Index(wsVar.Key, "TF_VAR_") == 0 {
								tt := strings.Replace(wsVar.Key, "TF_VAR_", "", 1)
								if contains(strings.ToLower(tt), sensitiveTfcVariablePattens) {
									varVialations = append(varVialations, *newVarVialation(org.Name, workspaces.Name, string(wsVar.Category), wsVar.Key))
								}
							} //should add else to handle TF_VAR_var style env variables
						case "terraform":
							if !wsVar.Sensitive && contains(strings.ToLower(wsVar.Key), sensitiveTfcVariablePattens) {
								varVialations = append(varVialations, *newVarVialation(org.Name, workspaces.Name, string(wsVar.Category), wsVar.Key))
							}

						}
					}
				}

			}
		}

		for i := 0; i < len(varVialations); i++ {
			var cc string
			if varVialations[i].category == "terraform" {
				cc = color.Yellow
			} else if strings.HasPrefix(varVialations[i].varName, "TF_VAR_") {
				cc = color.Yellow
			} else {
				cc = color.Red
			}
			fmt.Println("Orgnization:", varVialations[i].orgName, ",workspace:", varVialations[i].workspaceName, ",category:", varVialations[i].category, ",Variable:", cc+varVialations[i].varName+color.Reset)
		}

	}
}
