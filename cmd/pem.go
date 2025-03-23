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
		Short: "Generate pem certificate and private key and write to disk.",
		Long: "Generate pem certificate and private key and write to disk. This command is currently " +
		  "primitive in terms of configurable fields. Seek an alternative tool if a more refined certificate is " +
		  "needed.",
		Example: "gosplit pem --pem-cert-file rando-crt.pem --pem-key-file rando-key.pem " +
		  "--org-name \"Rando Org\" -i 192.168.1.5 -i 192.168.1.6 -s RandoName1 -s RandoName2",
		Run: runPem,
	}
	pemOrgName string
	pemIps     []string
	pemNames   []string
)

func init() {
	pemCmd.Flags().StringVarP(&pemOrgName, "org-name", "n", "", "Organization name")
	pemCmd.Flags().StringSliceVarP(&pemIps, "ips", "i", []string{}, "IP addresses")
	pemCmd.Flags().StringSliceVarP(&pemNames, "names", "s", []string{}, "DNS names")
	prExit(flagRequiredMsg, pemCmd.MarkFlagRequired("org-name"))
	prExit(flagRequiredMsg, pemCmd.MarkFlagRequired("ips"))
	prExit(flagRequiredMsg, pemCmd.MarkFlagRequired("names"))
}

func runPem(_ *cobra.Command, _ []string) {
	var ips []net.IP
	for _, i := range pemIps {
		ip := net.ParseIP(i)
		prExit(fmt.Sprintf("bad ip address (%s)", i), errors.New("failed to parse supplied ip address"))
		ips = append(ips, ip)
	}

	crt, err := gosplit.GenSelfSignedCert(pkix.Name{Organization: []string{pemOrgName}}, ips, pemNames)
	if err != nil {
		prExit("failed to generate certificate", err)
	}

	var crtWriter, keyWriter io.Writer
	if crtWriter, err = openFile(pemCertFile); err != nil {
		prExit("failed to open certificate file for writing", err)
	} else if keyWriter, err = openFile(pemKeyFile); err != nil {
		prExit("failed to open key file for writing", err)
	} else if err = gosplit.WritePEM(*crt, crtWriter, keyWriter); err != nil {
		prExit("failed to write certificate and key files", err)
	}
}
