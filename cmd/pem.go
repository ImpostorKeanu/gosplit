package main

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/impostorkeanu/gosplit"
	"github.com/spf13/cobra"
	"io"
	"net"
)

var (
	pemCmd = &cobra.Command{
		Use:   "pem",
		Short: "Generate a pem certificate",
		Long: "Generate a pem certificate and write to disk. This command is currently\n" +
		  "primitive in terms of configurable fields. Seek an alternative tool if a\n" +
		  "more refined certificate is needed.",
		Example: `
gosplit pem --cert-file crt.pem --key-file key.pem \
  --org-name \"Rando Org\" \
  -i 192.168.1.5 -i 192.168.1.6 \
  -s RandoName1 -s RandoName2`,
		Run: runPem,
	}
	pemOrgName string
	pemIps     []string
	pemNames   []string
)

func init() {
	pemCmd.Flags().StringVarP(&pemOrgName, "org-name", "n", "GoSplit", "Organization name for the cert")
	pemCmd.Flags().StringSliceVarP(&pemIps, "ips", "i", []string{"127.0.0.1"}, "IP addresses for the cert")
	pemCmd.Flags().StringSliceVarP(&pemNames, "names", "s", []string{"gosplit"}, "DNS names for the cert")
}

func runPem(_ *cobra.Command, _ []string) {
	var ips []net.IP
	for _, i := range pemIps {
		ip := net.ParseIP(i)
		if ip == nil {
			prExit(
				errors.New("failed to parse supplied ip address"),
				fmt.Sprintf("bad ip address (%s)", i))
		}
		ips = append(ips, ip)
	}

	crt, err := gosplit.GenSelfSignedCert(pkix.Name{Organization: []string{pemOrgName}}, ips, pemNames)
	if err != nil {
		prExit(err, "failed to generate certificate")
	}

	var crtWriter, keyWriter io.Writer
	crtWriter, err = openFile(pemCertFile)
	prExit(err, "failed to open certificate file for writing")
	keyWriter, err = openFile(pemKeyFile)
	prExit(err, "failed to open key file for writing")

	err = gosplit.WritePEM(*crt, crtWriter, keyWriter)
	closeWriter(crtWriter)
	closeWriter(keyWriter)

	prExit(err, "failed to write certificate and key files")
}
