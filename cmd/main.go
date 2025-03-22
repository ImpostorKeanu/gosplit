package main

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "gosplit",
		Short: "Run a split server.",
		Long:  "Run a split server.",
	}
	pemCertFile string // file containing pem cert
	pemKeyFile  string // file containing pem key
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&pemCertFile, "pem-cert-file", "p", "",
		"File to receive PEM certificate from")
	rootCmd.PersistentFlags().StringVarP(&pemKeyFile, "pem-key-file", "k", "",
		"File to read certificate key from (required with --pem-cert-file)")
	if err := rootCmd.MarkPersistentFlagRequired("pem-cert-file"); err != nil {
		panic(err)
	} else if err = rootCmd.MarkPersistentFlagRequired("pem-key-file"); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(pemCmd, runCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
