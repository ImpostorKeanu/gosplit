package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/impostorkeanu/gosplit"
	"github.com/spf13/cobra"
	"io"
	"net"
	"os"
)

var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run a TLS aware TCP proxy server",
		Long:  "Run a TLS aware TCP proxy server",
		Run:   runServer,
		Example: `
gosplit run --listen-addr 192.168.1.2:10000 --downstream-addr 192.168.1.3:10000 \
  --cert-file crt.pem --key-file key.pem \
  --log-file /tmp/logs.json --nss-key-log-file /tmp/key-log.nss --data-log-file /tmp/data.json`,
	}

	listenAddr     string // socket where the proxy will listen
	downstreamAddr string // socket where the proxy will send traffic to
	logFile        string // standard log file
	dataLogFile    string // log file dedicated to extracted data
	dataToLog      bool   // log data to logFile instead of dataLogFile
	nssFile        string // file to receive nss keys to decrypt packet captures
)

type (
	teeWriter struct {
		io.Writer
	}
	newlineWriter struct {
		io.Writer
	}
)

func init() {
	runCmd.PersistentFlags().StringVarP(&listenAddr, "listen-addr", "l", "",
		"Socket the proxy server will listen on, e.g., 192.168.1.86:443")
	runCmd.PersistentFlags().StringVarP(&downstreamAddr, "downstream-addr", "d", "",
		"Socket that the proxy will send traffic to, e.g., 192.168.1.250:443")
	runCmd.PersistentFlags().StringVarP(&logFile, "log-file", "x", "gosplit.log",
		"File to write JSON log messages to")
	runCmd.PersistentFlags().StringVarP(&dataLogFile, "data-log-file", "o", "",
		"File to receive intercepted data in JSON format (takes precedence over --data-to-log)")
	runCmd.PersistentFlags().BoolVarP(&dataToLog, "data-to-log", "y", false,
		"Results in data being sent to the log file instead of --data-log-file")
	runCmd.PersistentFlags().StringVarP(&nssFile, "nss-key-log-file", "n", "",
		"File to receive Network Security Services key log file for Wireshark")
	prExit(runCmd.MarkPersistentFlagRequired("listen-addr"), flagRequiredMsg)
	prExit(runCmd.MarkPersistentFlagRequired("downstream-addr"), flagRequiredMsg)
}

func openFile(n string) (*os.File, error) {
	return os.OpenFile(n, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
}

func dstOpenFile(dst *io.Writer, n string, newline bool) error {
	if n == "" {
		return nil
	}
	d, err := openFile(n)
	if newline {
		*dst = &newlineWriter{d}
	} else {
		*dst = d
	}
	return err
}

func (w *teeWriter) Write(p []byte) (n int, err error) {
	fmt.Println(string(p))
	return w.Writer.Write(p)
}

func (w *newlineWriter) Write(p []byte) (n int, err error) {
	p = append(p, '\n')
	return w.Writer.Write(p)
}

func runServer(cmd *cobra.Command, args []string) {

	// initialize the config
	// - any writers not configured send output to io.Discard
	// - KeyLogWriter for downstream tls nss is configured later
	cfg := config{
		logWriter:        io.Discard,
		dataWriter:       io.Discard,
		nssWriter:        io.Discard,
		dataToLog:        dataToLog,
		downstreamTlsCfg: &tls.Config{InsecureSkipVerify: true},
	}

	//=================================
	// PREPARE SERVER TLS AND ADDRESSES
	//=================================

	t, err := tls.LoadX509KeyPair(pemCertFile, pemKeyFile)
	prExit(err, "error while loading x509 keypair")
	cfg.proxyCrt = &t

	cfg.proxyIP, cfg.proxyPort, err = net.SplitHostPort(listenAddr)
	prExit(err, "error while parsing --listen-addr")

	cfg.downstreamIP, cfg.downstreamPort, err = net.SplitHostPort(downstreamAddr)
	prExit(err, "error while parsing --downstream-addr")

	//=====================
	// PREPARE OUTPUT FILES
	//=====================

	err = dstOpenFile(&cfg.logWriter, logFile, true)
	prExit(err, "error while opening log file for writing")

	// tee records destined to the log file to stdout
	cfg.logWriter = &teeWriter{cfg.logWriter}

	err = dstOpenFile(&cfg.dataWriter, dataLogFile, true)
	prExit(err, "error while data file for writing")

	err = dstOpenFile(&cfg.nssWriter, nssFile, false)
	prExit(err, "error while opening nss key file file for writing")

	if cfg.nssWriter != io.Discard {
		// send nss records to log file
		cfg.downstreamTlsCfg.KeyLogWriter = cfg.nssWriter
	}

	//===============
	// RUN THE SERVER
	//===============

	fmt.Printf("Starting server on %s\n", listenAddr)
	err = gosplit.NewProxyServer(cfg).Serve(context.Background())

	prExit(err, "error running the proxy server")
}
