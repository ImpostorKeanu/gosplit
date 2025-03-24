package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	gs "github.com/impostorkeanu/gosplit"
	"io"
)

const (
	victimDataSender     = "victim"
	downstreamDataSender = "downstream"
)

type (

	// config implements gs.Cfg.
	config struct {
		proxyIP          string           // local ip the proxy server will bind to
		proxyPort        string           // local port the proxy server will bind to
		downstreamIP     string           // downstream ip the proxy server connects to
		downstreamPort   string           // downstream port the proxy server connects to
		dataToLog        bool             // send data events to logWriter AND dataWriter
		logWriter        io.Writer        // writer for logs
		dataWriter       io.Writer        // writer for data
		nssWriter        io.Writer        // key log writer for tls dissection
		proxyCrt         *tls.Certificate // certificate presented by the proxy server
		downstreamTlsCfg *tls.Config      // tls config used to connect to the downstream
	}

	dataLog struct {
		Level       string `json:"level,omitempty"`
		Sender      string `json:"sender"`
		Data        string `json:"data"`
		gs.ConnInfo `json:",inline"`
	}
)

func (c config) GetProxyTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr) (*tls.Config, error) {
	// TODO enhance this method to generate the certificate dynamically
	//  - generated certificates should be cached for reuse
	if c.proxyCrt == nil {
		return nil, errors.New("proxyCrt is nil")
	}
	return &tls.Config{InsecureSkipVerify: true, KeyLogWriter: c.nssWriter,
		Certificates: []tls.Certificate{*c.proxyCrt}}, nil
}

func (c config) GetProxyAddr() (ip string, port string, err error) {
	return c.proxyIP, c.proxyPort, nil
}

func (c config) GetDownstreamTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr) (*tls.Config, error) {
	return c.downstreamTlsCfg, nil
}

func (c config) GetDownstreamAddr(_ gs.ProxyAddr, _ gs.VictimAddr) (ip string, port string, err error) {
	return c.downstreamIP, c.downstreamPort, nil
}

func (c config) RecvLog(fields gs.LogRecord) {
	// marshal the log record and write to logWriter
	if b, err := json.Marshal(fields); err != nil {
		println("error marshaling log record: ", err.Error())
	} else if _, err = c.logWriter.Write(b); err != nil {
		println("error writing log record: ", err.Error())
	}
}

func (c config) RecvVictimData(b []byte, cI gs.ConnInfo) {
	if c.dataWriter == nil {
		return
	}
	c.writeDataLog(victimDataSender, b, cI)
}

func (c config) RecvDownstreamData(b []byte, cI gs.ConnInfo) {
	if c.dataWriter == nil {
		return
	}
	c.writeDataLog(downstreamDataSender, b, cI)
}

// writeDataLog writes data extracted through proxying to dataWriter and
// optionally the logWriter.
func (c config) writeDataLog(sender string, b []byte, cI gs.ConnInfo) {

	// construct the dataLog
	dL := dataLog{
		Sender:   sender,
		ConnInfo: cI,
		Data:     base64.StdEncoding.EncodeToString(b),
	}

	// marshal the dataLog and write to the data writer
	var err error
	if b, err = json.Marshal(dL); err != nil {
		println("error marshaling data log record: ", err.Error())
	} else if _, err = c.dataWriter.Write(b); err != nil {
		println("error writing data log record: ", err.Error())
	}

	if c.dataToLog {
		dL.Level = gs.DataLogLvl
		if b, err = json.Marshal(dL); err != nil {
			println("error marshaling data log record: ", err.Error())
		} else if _, err = c.logWriter.Write(b); err != nil {
			println("error writing data log record: ", err.Error())
		}
	}
}

func (c *config) closeWriters() {
	closeWriter(c.logWriter)
	closeWriter(c.dataWriter)
	closeWriter(c.nssWriter)
}
