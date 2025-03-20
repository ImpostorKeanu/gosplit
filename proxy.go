package gostrip

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
)

type (
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

// Serve TCP connections on port.
//
// This method blocks until ctx is canceled.
func (s *ProxyServer) Serve(ctx context.Context) (err error) {

	pIP, pPort, err := s.cfg.GetProxyAddr()
	if err != nil {
		return err
	}

	var l *proxyListener
	if x, err := net.Listen("tcp4", net.JoinHostPort(pIP, pPort)); err != nil {
		return err
	} else {
		l = &proxyListener{Listener: x, cfg: cfg{Cfg: s.cfg}}
	}

	pA := ProxyAddr{pIP, pPort}

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

			if e != nil && !errors.Is(e, net.ErrClosed) {
				vA, e2 := getVictimAddr(c)
				if e2 != nil {
					s.log(ErrorLogLvl, fmt.Sprintf("error acquiring victim address: %s", e2), pA, nil)
				}
				s.log(ErrorLogLvl, fmt.Sprintf("error while accepting new connection: %s", e), pA, &vA)
			}

			c = &proxyConn{
				Conn:      &peekConn{Conn: c, buf: bufio.NewReader(c)},
				proxyAddr: &pA,
				cfg:       l.cfg,
				s:         s}

			go c.(*proxyConn).handle(ctx)
		}
	}

	l.cfg.log(nil, InfoLogLvl, "stopping proxy server")
	return
}

func (s *ProxyServer) log(lvl, msg string, pA ProxyAddr, vA *VictimAddr) {
	if lr, ok := s.cfg.(LogReceiver); ok {
		cI := ConnInfo{
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
