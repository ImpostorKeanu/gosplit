package gosplit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

const (
	ProxyAddrCtxKey CtxKey = "proxy_addr"
)

type (
	CtxKey string

	// ProxyServer proxies TCP traffic to downstream servers during AITM
	// attacks. It exists mainly to accept and maintain a count of connections.
	//
	// Use NewProxyServer to initialize a new server.
	//
	// ConnCount can be used to determine the number of connections active
	// with the server.
	ProxyServer struct {
		cfg       Cfg
		connCount atomic.Int32
	}

	// proxyListener provides configuration information to Listener.
	proxyListener struct {
		net.Listener
		cfg cfg
	}
)

// ConnCount returns the total number of active connections to the
// server.
func (s *ProxyServer) ConnCount() int {
	return int(s.connCount.Load())
}

// NewProxyServer initializes a ProxyServer.
func NewProxyServer(cfg Cfg) *ProxyServer {
	return &ProxyServer{cfg: cfg}
}

// Serve a TCP server capable of handling TLS connections.
//
// The method obtains the IP and port the server binds to in
// on of two ways:
//
// 1. ProxyAddr
// 2. Or dynamically by having the cfg embedded in ProxyServer implement ProxyAddrGetter.
//
// Supplying a ProxyAddr argument takes precedence over ProxyAddrGetter.
func (s *ProxyServer) Serve(ctx context.Context, listener net.Listener) (err error) {

	var pIP, pPort string
	if pIP, pPort, err = net.SplitHostPort(listener.Addr().String()); err != nil {
		s.log(ErrorLogLvl, "failed to parse ip and port from listener", ProxyAddr{}, nil)
	}

	l := &proxyListener{Listener: listener, cfg: cfg{Cfg: s.cfg}}
	pA := ProxyAddr{Addr: Addr{IP: pIP, Port: pPort}}

	s.log(InfoLogLvl, "starting proxy server", pA, nil)

	context.AfterFunc(ctx, func() {
		if e := l.Close(); e != nil {
			s.log(ErrorLogLvl, "error closing proxy server listener", pA, nil)
		}
	})

ctrl:
	for {
		select {
		case <-ctx.Done():
			break ctrl
		default:
			c, e := l.Accept()

			if errors.Is(e, net.ErrClosed) {
				err = nil
				s.log(InfoLogLvl, "proxy server listener closed", pA, nil)
				break ctrl
			} else if e != nil {
				vA, e2 := getVictimAddr(c)
				if e2 != nil {
					s.log(ErrorLogLvl, fmt.Sprintf("error acquiring victim address: %s", e2), pA, nil)
				} else {
					s.log(ErrorLogLvl, fmt.Sprintf("error while accepting new connection: %s", e), pA, &vA)
				}
				break ctrl
			}

			c = &proxyConn{
				Conn:      &peekConn{Conn: c, buf: bufio.NewReader(c)},
				proxyAddr: &pA,
				cfg:       l.cfg,
				s:         s}

			go c.(*proxyConn).handle(ctx)
		}
	}

	if l != nil {
		l.Close()
	}

	l.cfg.log(nil, InfoLogLvl, "stopping proxy server")
	return
}

func (s *ProxyServer) log(lvl, msg string, pA ProxyAddr, vA *VictimAddr) {
	if lr, ok := s.cfg.(LogReceiver); ok {
		cI := ConnInfo{
			Time:      time.Now(),
			ProxyAddr: pA,
		}
		if vA != nil {
			cI.VictimAddr = *vA
		}
		lr.RecvLog(LogRecord{
			Level:    lvl,
			Msg:      msg,
			ConnInfo: cI,
		})
	}
}
