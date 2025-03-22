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
		Short: "Run a split proxy",
		Long:  "Run a split proxy",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config{
				logWriter:        io.Discard,
				dataWriter:       io.Discard,
				nssWriter:        io.Discard,
				dataToLog:        dataToLog,
				downstreamTlsCfg: &tls.Config{InsecureSkipVerify: true},
			}

			if t, err := tls.LoadX509KeyPair(pemCertFile, pemKeyFile); err != nil {
				panic(err)
			} else {
				cfg.proxyCrt = &t
			}

			var err error
			if err = dstOpenFile(&cfg.logWriter, logFile, true); err != nil {
				panic(err)
			}
			cfg.logWriter = &teeWriter{cfg.logWriter}

			if err = dstOpenFile(&cfg.dataWriter, dataLogFile, true); err != nil {
				panic(err)
			}

			if err = dstOpenFile(&cfg.nssWriter, nssFile, false); err != nil {
				panic(err)
			}
			if cfg.nssWriter != io.Discard {
				cfg.downstreamTlsCfg.KeyLogWriter = cfg.nssWriter
			}

			if cfg.proxyAddr, cfg.proxyPort, err = net.SplitHostPort(listenAddr); err != nil {
				panic(err)
			} else if cfg.downstreamAddr, cfg.downstreamPort, err = net.SplitHostPort(downstreamAddr); err != nil {
				panic(err)
			}

			fmt.Printf("Starting server on %s\n", listenAddr)
			if err = gosplit.NewProxyServer(cfg).Serve(context.Background()); err != nil {
				panic(err)
			}
		},
	}

	listenAddr     string // socket where the proxy will listen
	downstreamAddr string // socket where the proxy will send traffic to
	logFile        string // standard log file
	dataLogFile    string // log file dedicated to extracted data
	dataToLog      bool   // log data to logFile instead of dataLogFile
	nssFile        string // file to receive nss keys to decrypt packet captures
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

	if err := runCmd.MarkPersistentFlagRequired("listen-addr"); err != nil {
		panic(err)
	} else if err = runCmd.MarkPersistentFlagRequired("downstream-addr"); err != nil {
		panic(err)
	}
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

type (
	teeWriter struct {
		io.Writer
	}
	newlineWriter struct {
		io.Writer
	}
)

func (w *teeWriter) Write(p []byte) (n int, err error) {
	fmt.Println(string(p))
	return w.Writer.Write(p)
}

func (w *newlineWriter) Write(p []byte) (n int, err error) {
	p = append(p, '\n')
	return w.Writer.Write(p)
}
