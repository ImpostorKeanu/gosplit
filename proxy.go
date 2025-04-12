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
		l         net.Listener
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
func NewProxyServer(cfg Cfg, l net.Listener) *ProxyServer {
	return &ProxyServer{cfg: cfg, l: l}
}

// Serve a TCP server capable of handling TLS connections.
//
// The method obtains the IP and port the server binds to in
// on of two ways:
//
// 1. Addr
// 2. Or dynamically by having the cfg embedded in ProxyServer implement ProxyAddrGetter.
//
// Supplying a Addr argument takes precedence over ProxyAddrGetter.
func (s *ProxyServer) Serve(ctx context.Context) (err error) {

	var pIP, pPort string
	if pIP, pPort, err = net.SplitHostPort(s.l.Addr().String()); err != nil {
		s.log(ErrorLogLvl, "failed to parse ip and port from l", Addr{}, nil)
	}

	l := &proxyListener{Listener: s.l, cfg: cfg{Cfg: s.cfg}}
	pA := Addr{IP: pIP, Port: pPort}

	s.log(InfoLogLvl, "starting proxy server", pA, nil)

	context.AfterFunc(ctx, func() {
		if e := l.Close(); e != nil {
			s.log(ErrorLogLvl, "error closing proxy server l", pA, nil)
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
				e = fmt.Errorf("error accepting connection: %v", e)
				var vA *Addr
				if v, vE := getVictimAddr(c); vE != nil {
					e = fmt.Errorf("error getting victim address: %v (while handling: %v)", vE, e)
				} else {
					vA = &v
				}
				s.log(ErrorLogLvl, err.Error(), pA, vA)
				break ctrl
			}

			c = &proxyConn{
				Conn:      &peekConn{Conn: c, buf: bufio.NewReader(c)},
				proxyAddr: &pA,
				cfg:       l.cfg,
				s:         s}

			go c.(*proxyConn).handle()
		}
	}

	if l != nil {
		if err := l.Close(); err != nil {
			s.log(ErrorLogLvl, "error closing proxy server listener", pA, nil)
		}
	}

	l.cfg.log(nil, InfoLogLvl, "proxy server stopped")
	return
}

func (s *ProxyServer) log(lvl, msg string, pA Addr, vA *Addr) {
	if lr, ok := s.cfg.(LogReceiver); ok {
		cI := ConnInfo{
			Time:  time.Now(),
			Proxy: pA,
		}
		if vA != nil {
			cI.Victim = *vA
		}
		lr.RecvLog(LogRecord{
			Level:    lvl,
			Msg:      msg,
			ConnInfo: cI,
		})
	}
}
