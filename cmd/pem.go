package main

import (
	"crypto/x509/pkix"
	"github.com/impostorkeanu/gosplit"
	"github.com/spf13/cobra"
	"io"
	"net"
)

var (
	pemCmd = &cobra.Command{
		Use:   "pem",
		Short: "Generate pem certificate and private key and write to disk",
		Long:  "Generate pem certificate and private key and write to disk",
		Run: func(cmd *cobra.Command, args []string) {
			var ips []net.IP
			for _, i := range pemIps {
				ips = append(ips, net.ParseIP(i))
			}

			crt, err := gosplit.GenSelfSignedCert(pkix.Name{Organization: []string{pemOrgName}}, ips, pemNames)
			if err != nil {
				panic(err)
			}

			var crtWriter, keyWriter io.Writer
			if crtWriter, err = openFile(pemCertFile); err != nil {
				panic(err)
			}
			if keyWriter, err = openFile(pemKeyFile); err != nil {
				panic(err)
			}

			if err = gosplit.WritePEM(*crt, crtWriter, keyWriter); err != nil {
				panic(err)
			}
		},
	}
	pemOrgName string
	pemIps     []string
	pemNames   []string
)

func init() {
	pemCmd.Flags().StringVarP(&pemOrgName, "org-name", "n", "", "Organization name")
	pemCmd.Flags().StringSliceVarP(&pemIps, "ips", "i", []string{}, "IP addresses")
	pemCmd.Flags().StringSliceVarP(&pemNames, "names", "s", []string{}, "DNS names")
	if err := pemCmd.MarkFlagRequired("org-name"); err != nil {
		panic(err)
	} else if err = pemCmd.MarkFlagRequired("ips"); err != nil {
		panic(err)
	} else if err = pemCmd.MarkFlagRequired("names"); err != nil {
		panic(err)
	}
}
