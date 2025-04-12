package gosplit

import (
	"crypto/tls"
	"time"
)

const (
	InfoLogLvl  = "info"
	ErrorLogLvl = "error"
	DebugLogLvl = "debug"
	DataLogLvl  = "data"
)

type (

	// Cfg establishes methods used by ProxyServer to run and handle
	// connections.
	//
	// Cfg type functionality can be extended by implementing the
	// following interfaces:
	//
	// - Handshaker to customize TLS fingerprinting
	// - ConnInfoReceiver to receive notifications on when connections are started/ended
	// - LogReceiver to handle LogRecord events
	// - DataReceiver to handle data captured while dissecting connections
	Cfg interface {
		// GetProxyTLSConfig gets the tls config used by the proxy
		// upon handshake detection.
		//
		// This allows implementors to retrieve custom configurations
		// based on victim IP and port.
		//
		// Note: downstream is a pointer to allow capture of initial
		// data for connections that do not have a downstream. Implementors
		// should account for this.
		GetProxyTLSConfig(victim Addr, proxy Addr, downstream *Addr) (*tls.Config, error)
		// GetDownstreamAddr is used to retrieve the target downstream address
		// information. The current downstream IP address and proxy port are
		// passed to allow the underlying type to retrieve the right downstream.
		//
		// Note: a pointer is returned to allow for capture of initial
		// data for connections that do not have a downstream.
		GetDownstreamAddr(victim Addr, proxy Addr) (*Addr, error)
		// GetDownstreamTLSConfig allows implementers to customize the
		// TLS configuration that is used to connect to the downstream.
		//
		// Note: Unlike GetProxyTLSConfig and GetDownstreamAddr, a downstream
		// is required.
		GetDownstreamTLSConfig(victim Addr, proxy Addr, downstream Addr) (*tls.Config, error)
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
		RecvVictimData(ConnInfo, []byte)
		// RecvDownstreamData handles data returned
		// from downstream servers.
		RecvDownstreamData(ConnInfo, []byte)
	}

	// ProxyListenerAddr contains Addr information for a newly created
	// ProxyServer.
	ProxyListenerAddr struct {
		Addr      // ip and port that the listener is bound to
		Req  Addr // requested address sent by GetProxyAddr
	}

	// LogRecord is a standard set of fields that are send to Cfg.RecvLog.
	LogRecord struct {
		Level    string `json:"level"`
		Msg      string `json:"msg"`
		ConnInfo `json:"connInfo,inline,omitempty"`
	}

	// ConnInfo adds connection information to LogRecord.
	ConnInfo struct {
		Time   time.Time `json:"time"`
		Victim Addr      `json:"victim,omitempty"` // address of the victim
		Proxy  Addr      `json:"proxy,omitempty"`  // address of the proxy
		// Downstream address.
		//
		// Unlike Victim and Proxy, null values are supported to enable
		// capture of initial traffic and then terminating the connection.
		Downstream *Addr `json:"downstream"`
	}

	// Addr provides IP and Port fields for Addr,
	// Addr, and Addr, which are reflected
	// in ConnInfo instances.
	Addr struct {
		IP   string `json:"ip,omitempty"`
		Port string `json:"port,omitempty"`
	}

	// cfg embeds Cfg, giving us standardized calls to log events
	// and send messages regarding connection establishment and
	// death.
	cfg struct {
		Cfg
	}
)

func (a Addr) String() string {
	return a.IP + ":" + a.Port
}

// log sends log records to the server's cfg.
func (c cfg) log(conn *proxyConn, lvl, msg string) {
	if lr, ok := c.Cfg.(LogReceiver); ok {
		var cI ConnInfo
		cI.fill(conn)
		lr.RecvLog(LogRecord{Level: lvl, Msg: msg, ConnInfo: cI})
	}
}

// connStart increments the connection counter and notifies the server's
// cfg that a connection has started.
func (c cfg) connStart(conn *proxyConn) {
	conn.s.connCount.Add(1)
	if cir, ok := c.Cfg.(ConnInfoReceiver); ok {
		cir.RecvConnStart(newConnInfo(conn))
	}
}

// connEnd decrements the connection counter and notifies the server's
// cfg that a connection has ended.
func (c cfg) connEnd(conn *proxyConn) {
	conn.s.connCount.Add(-1)
	if cir, ok := c.Cfg.(ConnInfoReceiver); ok {
		cir.RecvConnEnd(newConnInfo(conn))
	}
}

// fill cI with information from the config and connection.
func (cI *ConnInfo) fill(p *proxyConn) {
	if cI.Time.IsZero() {
		cI.Time = time.Now()
	}
	if p.proxyAddr != nil {
		cI.Proxy = *p.proxyAddr
	}
	if p.victimAddr != nil {
		cI.Victim = *p.victimAddr
	}
	if p.downstreamAddr != nil {
		v := *p.downstreamAddr
		cI.Downstream = &v
	}
	return
}

func newConnInfo(conn *proxyConn) (i ConnInfo) {
	i.fill(conn)
	return i
}
