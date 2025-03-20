package gostrip

import (
	"fmt"
	"net"
)

func isHandshake(buf []byte) bool {
	// TODO SSL is no longer supported by the tls package
	//  may need to see about implementing it manually
	// https://tls12.xargs.org/#client-hello/annotated
	if len(buf) >= 2 && buf[0] == 0x16 && buf[1] == 0x03 {
		return true
	}
	return false
}

func getVictimAddr(c net.Conn) (vA VictimAddr, err error) {
	if vA.VictimIP, vA.VictimPort, err = net.SplitHostPort(c.RemoteAddr().String()); err != nil {
		err = fmt.Errorf("error parsing victim address information: %w", err)
	}
	return
}
