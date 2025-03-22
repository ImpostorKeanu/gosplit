package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	gs "github.com/impostorkeanu/gosplit"
	"io"
)

type (
	config struct {
		proxyAddr        string
		proxyPort        string
		downstreamAddr   string
		downstreamPort   string
		dataToLog        bool
		logWriter        io.Writer
		dataWriter       io.Writer
		nssWriter        io.Writer
		proxyCrt         *tls.Certificate
		downstreamTlsCfg *tls.Config
	}

	dataLog struct {
		Level       string `json:"level,omitempty"`
		Sender      string `json:"sender"`
		Data        string `json:"data"`
		gs.ConnInfo `json:",inline"`
	}
)

func (c config) GetProxyTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr) (*tls.Config, error) {
	if c.proxyCrt == nil {
		return nil, errors.New("proxyCrt is nil")
	}
	return &tls.Config{InsecureSkipVerify: true, KeyLogWriter: c.nssWriter,
		Certificates: []tls.Certificate{*c.proxyCrt}}, nil
}

func (c config) GetProxyAddr() (ip string, port string, err error) {
	return c.proxyAddr, c.proxyPort, nil
}

func (c config) GetDownstreamTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr) (*tls.Config, error) {
	return c.downstreamTlsCfg, nil
}

func (c config) GetDownstreamAddr(_ gs.ProxyAddr, _ gs.VictimAddr) (ip string, port string, err error) {
	return c.downstreamAddr, c.downstreamPort, nil
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
	c.writeDataLog(gs.VictimDataSender, b, cI)
}

func (c config) RecvDownstreamData(b []byte, cI gs.ConnInfo) {
	if c.dataWriter == nil {
		return
	}
	c.writeDataLog(gs.DownstreamDataSender, b, cI)
}

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
