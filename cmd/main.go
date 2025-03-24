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
	rootCmd.PersistentFlags().StringVarP(&pemCertFile, "cert-file", "c", "",
		"File to receive PEM certificate from")
	rootCmd.PersistentFlags().StringVarP(&pemKeyFile, "key-file", "k", "",
		"File to read PEM key from")
	prExit(rootCmd.MarkPersistentFlagRequired("cert-file"), flagRequiredMsg)
	prExit(rootCmd.MarkPersistentFlagRequired("key-file"), flagRequiredMsg)
	rootCmd.AddCommand(pemCmd, runCmd)
}

func main() {
	prExit(rootCmd.Execute(), "error while running server")
}
