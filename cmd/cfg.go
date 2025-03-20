package cmd

import (
	"crypto/tls"
	"encoding/json"
	gs "github.com/impostorkeanu/gosplit"
	"io"
)

type (
	Config struct {
		proxyAddr        string
		proxyPort        string
		downstreamAddr   string
		downstreamPort   string
		nssWriter        io.Writer
		proxyCrt         *tls.Certificate
		downstreamTlsCfg *tls.Config
	}
)

func (c Config) GetProxyTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       c.nssWriter,
	}
	if c.proxyCrt != nil {
		cfg.Certificates = []tls.Certificate{*c.proxyCrt}
	} else {
		cfg.GetCertificate = gs.GenCert
	}
	return cfg, nil
}

func (c Config) GetProxyAddr() (ip string, port string, err error) {
	return c.proxyAddr, c.proxyPort, nil
}

func (c Config) GetDownstreamTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr) (*tls.Config, error) {
	return c.downstreamTlsCfg, nil
}

func (c Config) GetDownstreamAddr(_ gs.ProxyAddr, _ gs.VictimAddr) (ip string, port string, err error) {
	return c.downstreamAddr, c.downstreamPort, nil
}

func (c Config) RecvLog(fields gs.LogRecord) {
	b, _ := json.Marshal(fields)
	println(string(b))
}

func (c Config) HandleVictimData(b []byte, _ gs.ConnInfo) {
	println("victim data", "--->", string(b))
}

func (c Config) HandleDownstreamData(b []byte, _ gs.ConnInfo) {
	println("victim data", "--->", string(b))
}
