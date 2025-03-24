package main

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use: "gosplit",
		Long: "GoSplit is an intercepting TCP server that can handle simple TLS tunnels\n" +
		  "and log data to disk.",
	}
	pemCertFile string // file containing pem cert
	pemKeyFile  string // file containing pem key
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&pemCertFile, "pem-cert-file", "p", "",
		"File to receive PEM certificate from")
	rootCmd.PersistentFlags().StringVarP(&pemKeyFile, "pem-key-file", "k", "",
		"File to read certificate key from")
	prExit(rootCmd.MarkPersistentFlagRequired("pem-cert-file"), flagRequiredMsg)
	prExit(rootCmd.MarkPersistentFlagRequired("pem-key-file"), flagRequiredMsg)
	rootCmd.AddCommand(pemCmd, runCmd)
}

func main() {
	prExit(rootCmd.Execute(), "error while running server")
}
