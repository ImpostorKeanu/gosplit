package cmd

import (
	"crypto/tls"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"net"
	"os"
)

var (
	run = &cobra.Command{
		Use:   "run",
		Short: "Run a gosplit proxy",
		Long:  "Run a gosplit proxy",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	listenAddr     string // socket where the proxy will listen
	downstreamAddr string // socket where the proxy will send traffic to
	logFile        string // standard log file
	dataLogFile    string // log file dedicated to extracted data
	dataToLog      bool   // log data to logFile instead of dataLogFile
	nssFile        string // file to receive nss keys to decrypt packet captures
	pemCertFile    string // file containing pem cert
	pemKeyFile     string // file containing pem key
)

func init() {
	run.PersistentFlags().StringVarP(&listenAddr, "listen-addr", "l", "",
		"Socket the proxy server will listen on, e.g., 192.168.1.86:443")
	run.PersistentFlags().StringVarP(&downstreamAddr, "downstream-addr", "d", "",
		"Socket that the proxy will send traffic to, e.g., 192.168.1.250:443")
	run.PersistentFlags().StringVarP(&logFile, "log-file", "l", "gosplit.log",
		"File to write JSON log messages to")
	run.PersistentFlags().StringVarP(&dataLogFile, "data-log-file", "o", "",
		"File to receive intercepted data in JSON format (takes precedence over --data-to-log)")
	run.PersistentFlags().BoolVarP(&dataToLog, "data-to-log", "x", false,
		"Results in data being sent to the log file instead of --data-log-file")
	run.PersistentFlags().StringVarP(&nssFile, "nss-key-log-file", "n", "",
		"File to receive Network Security Services key log file for Wireshark")
	run.PersistentFlags().StringVarP(&pemCertFile, "pem-cert-file", "p", "",
		"File to receive PEM certificate from")
	run.PersistentFlags().StringVarP(&pemKeyFile, "pem-key-file", "k", "",
		"File to read certificate key from (required with --pem-cert-file)")

	var err error
	if err = run.MarkPersistentFlagRequired("listen-addr"); err != nil {
		panic(err)
	} else if err = run.MarkPersistentFlagRequired("downstream-addr"); err != nil {
		panic(err)
	}

	var tlsCert tls.Certificate
	if pemCertFile != "" && pemKeyFile == "" {
		panic(fmt.Errorf("--pem-cert and --pem-key-file must both specified together"))
	} else if pemCertFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(pemCertFile, pemKeyFile)
		if err != nil {
			panic(err)
		}
	}

	var nssWriter io.Writer
	if nssFile != "" {
		if nssWriter, err = os.OpenFile(nssFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err != nil {
			panic(err)
		}
	}

	cfg := Config{
		proxyCrt:  &tlsCert,
		nssWriter: nssWriter,
	}

	if cfg.proxyAddr, cfg.proxyPort, err = net.SplitHostPort(listenAddr); err != nil {
		panic(err)
	} else if cfg.downstreamAddr, cfg.downstreamPort, err = net.SplitHostPort(listenAddr); err != nil {
		panic(err)
	}
}
