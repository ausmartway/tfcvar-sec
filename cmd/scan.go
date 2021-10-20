/*
Copyright © 2021 Yulei Liu <yulei.liu@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/TwiN/go-color"
	tfe "github.com/hashicorp/go-tfe"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const Hostname = "app.terraform.io"

var token string
var fixCritial, fixWarning bool
var numOrg, numWorkspace, numVar, numCritical, numWarning, numCriticalFix, numWarningFix int

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&token, "token", "", "Terraform Cloud/Enterprise personal/team/orgnisation token")
	scanCmd.Flags().BoolVar(&fixCritial, "fixcritial", false, "fix Critical variables by marking them sensitive,default to false")
	scanCmd.Flags().BoolVar(&fixCritial, "fixwarning", false, "fix Warning variables by marking them sensitive,default to false")

}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scans Terraform Cloud for sensitive varaibles",
	Long:  `Scans Terraform Cloud for sensitive varaibles`,
	Run: func(cmd *cobra.Command, args []string) {
		initConfig()
		scan(Hostname, token)
	},
}

var sensitiveTfcVariablePattens = []string{
	//This list is use to *guess* if a terraform variable contains a secret. Any terraform variable name contains below list is considered sensitive.
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
	//This is used to determain if an enviroment variable contains a provider secret that in general should be marked as senstive.

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

	//Docker
	"DOCKER_REGISTRY_PASS": true,

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

	//Linode
	"LINODE_TOKEN": true,
}

//flat structure
type varVialation struct {
	orgName       string
	workspaceName string
	category      string
	varName       string
}

var varVialations []varVialation

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

// initConfig reads in credential file and ENV variables if set.
func initConfig() {
	var home string
	var err error

	if token == "" {
		if os.Getenv("TFE_TOKEN") != "" {
			fmt.Fprintln(os.Stderr, "Using enviroment varialbe TFE_TOKEN")
			token = os.Getenv("TFE_TOKEN")
		} else {
			// Find config directory.
			if runtime.GOOS == "windows" {
				home, err = os.UserConfigDir()
				home = home + "\\terraform.d\\"
				cobra.CheckErr(err)
			} else if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
				home, err = os.UserHomeDir()
				home = home + "/.terraform.d/"
				cobra.CheckErr(err)
			}

			// Search config in home directory with name "credentials.tfrc.json".
			viper.AddConfigPath(home)
			viper.SetConfigType("json")
			viper.SetConfigName("credentials.tfrc.json")
			// If a config file is found, read it in.
			if err := viper.ReadInConfig(); err == nil {
				fmt.Fprintln(os.Stderr, "Using credential file:", viper.ConfigFileUsed())
				token = viper.GetString("credentials." + Hostname + ".token")
			} else {
				fmt.Fprintln(os.Stderr, "error:", "No token provided on cli")
				fmt.Fprintln(os.Stderr, "error:", err)
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "Using token provided")
	}
}

func scan(hostname string, token string) {
	tfeHost := "https://" + hostname
	tfeToken := token

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
		numOrg = numOrg + len(orgs.Items)
		for _, org := range orgs.Items {
			//for each org, get all workspaces
			ws, err := client.Workspaces.List(ctx, org.Name, tfe.WorkspaceListOptions{})
			if err != nil {
				log.Fatal(err)
			} else {
				numWorkspace = numWorkspace + len(ws.Items)
				for _, workspaces := range ws.Items {
					//for each workspace, get all variables
					variables, _ := client.Variables.List(ctx, workspaces.ID, tfe.VariableListOptions{
						ListOptions: tfe.ListOptions{
							PageNumber: 1,
							PageSize:   1000,
						},
					})
					//for each variable, see if it is in the list but not marked sensitive
					numVar = numVar + len(variables.Items)
					for _, wsVar := range variables.Items {
						switch wsVar.Category {
						case "env":
							if sensitiveEnvVariables[wsVar.Key] && !wsVar.Sensitive { //Enviroment variables is exact match
								numCritical = numCritical + 1
								varVialations = append(varVialations, *newVarVialation(org.Name, workspaces.Name, string(wsVar.Category), wsVar.Key))
								if fixCritial {
									numCriticalFix = numCriticalFix + 1
									_, updateErr := client.Variables.Update(ctx, workspaces.ID, wsVar.ID, tfe.VariableUpdateOptions{
										Sensitive: tfe.Bool(true),
									})
									if err != nil {
										fmt.Println(updateErr)
									}
								}
							} else if !wsVar.Sensitive && strings.Index(wsVar.Key, "TF_VAR_") == 0 { //if it is TF_VAR_something style
								tt := strings.Replace(wsVar.Key, "TF_VAR_", "", 1)
								if contains(strings.ToLower(tt), sensitiveTfcVariablePattens) {
									numWarning = numWarning + 1
									varVialations = append(varVialations, *newVarVialation(org.Name, workspaces.Name, string(wsVar.Category), wsVar.Key))
									if fixWarning {
										numWarningFix = numWarningFix + 1
										_, updateErr := client.Variables.Update(ctx, workspaces.ID, wsVar.ID, tfe.VariableUpdateOptions{
											Sensitive: tfe.Bool(true),
										})
										if err != nil {
											fmt.Println(updateErr)
										}
									}
								}
							}
						case "terraform":
							if !wsVar.Sensitive && contains(strings.ToLower(wsVar.Key), sensitiveTfcVariablePattens) {
								numWarning = numWarning + 1
								varVialations = append(varVialations, *newVarVialation(org.Name, workspaces.Name, string(wsVar.Category), wsVar.Key, workspaces.ID, wsVar.ID))
								if fixWarning {
									numWarningFix = numWarningFix + 1
									_, updateErr := client.Variables.Update(ctx, workspaces.ID, wsVar.ID, tfe.VariableUpdateOptions{
										Sensitive: tfe.Bool(true),
									})
									if err != nil {
										fmt.Println(updateErr)
									}
								}
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

		fmt.Println()
		fmt.Printf("Total number of Orgnisations scanned: %d\n", numOrg)
		fmt.Printf("Total number of Workspaces scanned: %d\n", numWorkspace)
		fmt.Printf("Total number of Variables scanned: %d\n", numVar)
		fmt.Println("Total number of "+color.Red+"Critical"+color.Reset+" variables detected:", numCritical)
		fmt.Println("Total number of "+color.Red+"Critical"+color.Reset+" variables fixed:", numCriticalFix)
		fmt.Println("Total number of "+color.Yellow+"Warning"+color.Reset+" variables detected:", numWarning)
		fmt.Println("Total number of "+color.Yellow+"Warning"+color.Reset+" variables fixed:", numWarningFix)
	}
}
