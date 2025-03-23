package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

const (
	flagRequiredMsg = "error marking flag required"
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
	prExit(flagRequiredMsg, rootCmd.MarkPersistentFlagRequired("pem-cert-file"))
	prExit(flagRequiredMsg, rootCmd.MarkPersistentFlagRequired("pem-key-file"))
	rootCmd.AddCommand(pemCmd, runCmd)
}

func main() {
	prExit("error while running server", rootCmd.Execute())
}

func prExit(msg string, err error) {
	if err != nil {
		println(fmt.Sprint("%s:", msg), err)
		os.Exit(1)
	}
}
