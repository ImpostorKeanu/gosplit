package gosplit

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"net"
	"testing"
)

var (
	proxyTlsConfig, downstreamTlsConfig *tls.Config
	tlsCert                             *tls.Certificate
)

type (
	Config struct{}
)

func (c Config) GetProxyTLSConfig(_ Addr, _ Addr, _ *Addr) (*tls.Config, error) {
	return proxyTlsConfig, nil
}

func (c Config) GetDownstreamTLSConfig(_ Addr, _ Addr, _ Addr) (*tls.Config, error) {
	return downstreamTlsConfig, nil
}

func (c Config) GetDownstreamAddr(_ Addr, _ Addr) (_ *Addr, err error) {
	return &Addr{IP: "192.168.86.3", Port: "10000"}, nil
	//return nil, nil
}

func (c Config) RecvConnStart(info ConnInfo) {
	b, _ := json.Marshal(info)
	println("new connection started: ", string(b))
}

func (c Config) RecvConnEnd(info ConnInfo) {
	b, _ := json.Marshal(info)
	println("connection ended:", string(b))
}

func (c Config) RecvLog(fields LogRecord) {
	b, _ := json.Marshal(fields)
	println(string(b))
}

func (c Config) RecvVictimData(_ ConnInfo, b []byte) {
	println("victim data", "--->", string(b))
}

func (c Config) RecvDownstreamData(_ ConnInfo, b []byte) {
	println("victim data", "--->", string(b))
}

func TestProxyServer_Serve(t *testing.T) {

	var err error
	tlsCert, err = GenSelfSignedCert(pkix.Name{Organization: []string{"Test Org"}},
		[]net.IP{net.ParseIP("127.0.0.1")},
		[]string{"localhost"}, nil)
	if err != nil {
		t.Error("failed to generate certificate", err)
		return
	}

	proxyTlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{*tlsCert},
	}
	downstreamTlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	type fields struct {
		cfg Cfg
	}
	type args struct {
		ctx context.Context
	}

	ctx, cancel := context.WithCancel(context.Background())
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{name: "test", fields: fields{cfg: Config{}}, args: args{ctx: ctx}, wantErr: false},
	}

	for _, tt := range tests {
		var err error
		t.Run(tt.name, func(t *testing.T) {
			s := &ProxyServer{
				cfg: tt.fields.cfg,
			}
			s.l, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Error("failed to start listener for server", err)
				return
			}
			t.Logf("started listener on %s", s.l.Addr().String())
			if err := s.Serve(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	cancel()
}
