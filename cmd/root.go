/*
Copyright © 2021 Yulei Liu

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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"version"
)

// rootCmd represents the base command when called without any subcommands
var (
	versionFlag bool
	rootCmd     = &cobra.Command{
		Use:   "tfcvar-sec",
		Short: "tfcvar-sec is a tool that scanns Terraform Cloud for insecure terraform/enviroment variables.",
		Long: `tfcvar-sec is a tool that scanns Terraform Cloud for insecure terraform/enviroment variables. 
Insecure enviroment variables are printed in Red with high level of confidence, terraform variables are guess work hence printed in Yellow.`,

		// Uncomment the following line if your bare application
		// has an action associated with it:
		Run: func(cmd *cobra.Command, args []string) {
			if versionFlag {
				fmt.Println(version.GetVersion("tfcvar-sec"))
				os.Exit(0)
			}

			if len(args) == 0 {
				cmd.Help()
				os.Exit(0)
			}

		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "Prints the Doormat CLI version")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
