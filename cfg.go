package gosplit

import (
	"crypto/tls"
)

const (
	InfoLogLvl           = "info"
	ErrorLogLvl          = "error"
	DebugLogLvl          = "debug"
	DataLogLvl           = "data"
	VictimDataSender     = "victim"
	DownstreamDataSender = "downstream"
)

type (

	// Cfg establishes methods used by ProxyServer to run and handle
	// connections.
	//
	// Implementors that also implement Handshaker allow for customization
	// of the TLS fingerprinting method.
	Cfg interface {
		// GetProxyAddr allows implementors to determine the listening
		// IP and port for the proxy side of the connection, which is
		// what victims connect to.
		GetProxyAddr() (ip string, port string, err error)
		// GetProxyTLSConfig gets the tls config used by the proxy
		// upon handshake detection.
		//
		// This allows implementors to retrieve custom configurations
		// based on victim IP and port.
		GetProxyTLSConfig(ProxyAddr, VictimAddr) (*tls.Config, error)
		// GetDownstreamAddr is used to retrieve the target downstream address
		// information. The current downstream IP address and proxy port are
		// passed to allow the underlying type to retrieve the right downstream.
		GetDownstreamAddr(ProxyAddr, VictimAddr) (ip string, port string, err error)
		// GetDownstreamTLSConfig allows implementers to customize the
		// TLS configuration that is used to connect to the downstream.
		GetDownstreamTLSConfig(ProxyAddr, VictimAddr) (*tls.Config, error)
	}

	// LogReceiver defines methods allowing implementors to receive
	// LogRecord objects from this module.
	LogReceiver interface {
		// RecvLog receives LogRecord at various points of execution as
		// connections are handled.
		RecvLog(LogRecord)
	}

	// ConnInfoReceiver defines methods that implementors can use to receive
	// ConnInfo events from this module.
	ConnInfoReceiver interface {
		// RecvConnStart receives connection information related to new
		// connections.
		RecvConnStart(ConnInfo)
		// RecvConnEnd receives connection information related to connections
		// that have ended.
		RecvConnEnd(ConnInfo)
	}

	// Handshaker defines methods used to check the initial data sent by
	// TCP clients to determine if they wish to speak TLS.
	Handshaker interface {
		// IsHandshake checks the byte slice for a TLS handshake.
		IsHandshake([]byte) bool
		// GetHandshakeLen indicates the number of bytes to consume
		// for fingerprinting.
		//
		// WARNING: the connections block until a downstream TCP connection
		// has received at least the number of bytes returned by this
		// method.
		GetHandshakeLen() int
	}

	// DataReceiver allows implementors to receive cleartext data
	// passing through the proxy.
	DataReceiver interface {
		// RecvVictimData handles victim data as it passes through
		// the proxy.
		RecvVictimData([]byte, ConnInfo)
		// RecvDownstreamData handles data returned
		// from downstream servers.
		RecvDownstreamData([]byte, ConnInfo)
	}

	// LogRecord is a standard set of fields that are send to Cfg.RecvLog.
	LogRecord struct {
		Level    string `json:"level"`
		Msg      string `json:"msg"`
		ConnInfo `json:"connInfo,inline,omitempty"`
	}

	// ConnInfo adds connection information to LogRecord.
	ConnInfo struct {
		VictimAddr     `json:"victim,omitempty"`
		ProxyAddr      `json:"proxy,omitempty"`
		DownstreamAddr `json:"downstream,omitempty"`
	}

	Addr struct {
		IP   string `json:"ip,omitempty"`
		Port string `json:"port,omitempty"`
	}

	VictimAddr struct {
		Addr `json:",inline,omitempty"`
	}

	ProxyAddr struct {
		Addr `json:",inline,omitempty"`
	}

	DownstreamAddr struct {
		Addr `json:",inline,omitempty"`
	}

	// cfg embeds Cfg, giving us standardized calls to log events
	// and send messages regarding connection establishment and
	// death.
	cfg struct {
		Cfg
	}
)

func (c cfg) log(conn *proxyConn, lvl, msg string) {
	if lr, ok := c.Cfg.(LogReceiver); ok {
		var cI ConnInfo
		cI.fill(conn)
		lr.RecvLog(LogRecord{Level: lvl, Msg: msg, ConnInfo: cI})
	}
}

func (c cfg) connStart(conn *proxyConn) {
	conn.s.connCount.Add(1)
	if cir, ok := c.Cfg.(ConnInfoReceiver); ok {
		cir.RecvConnStart(newConnInfo(conn))
	}
}

func (c cfg) connEnd(conn *proxyConn) {
	conn.s.connCount.Add(-1)
	if cir, ok := c.Cfg.(ConnInfoReceiver); ok {
		cir.RecvConnEnd(newConnInfo(conn))
	}
}

// fill cI with information from the config and connection.
func (cI *ConnInfo) fill(p *proxyConn) {
	if p.proxyAddr != nil {
		cI.ProxyAddr = *p.proxyAddr
	}
	if p.victimAddr != nil {
		cI.VictimAddr = *p.victimAddr
	}
	if p.downstreamAddr != nil {
		cI.DownstreamAddr = *p.downstreamAddr
	}
	return
}

func newConnInfo(conn *proxyConn) (i ConnInfo) {
	i.fill(conn)
	return i
}
