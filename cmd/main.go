package main

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "gosplit",
		Short: "Run a split server",
		Long:  "Run a split server",
	}
	pemCertFile string // file containing pem cert
	pemKeyFile  string // file containing pem key
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&pemCertFile, "pem-cert-file", "p", "",
		"File to receive PEM certificate from")
	rootCmd.PersistentFlags().StringVarP(&pemKeyFile, "pem-key-file", "k", "",
		"File to read certificate key from (required with --pem-cert-file)")
	prExit(rootCmd.MarkPersistentFlagRequired("pem-cert-file"), flagRequiredMsg)
	prExit(rootCmd.MarkPersistentFlagRequired("pem-key-file"), flagRequiredMsg)
	rootCmd.AddCommand(pemCmd, runCmd)
}

func main() {
	prExit(rootCmd.Execute(), "error while running server")
}
