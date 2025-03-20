package gosplit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"os"
	"testing"
)

var (
	proxyTlsConfig, downstreamTlsConfig *tls.Config
	tlsCert                             tls.Certificate
)

func init() {
	nssF, err := os.Create("/tmp/tls_key_log.nss")
	if err != nil {
		// TODO
		panic(err)
	}
	if tlsCert, err = tls.LoadX509KeyPair("/tmp/cert.pem", "/tmp/key.pem"); err != nil {
		log.Fatal(err)
	}
	proxyTlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       nssF,
		Certificates:       []tls.Certificate{tlsCert},
	}
	downstreamTlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
}

type (
	Config struct{}
)

func (c Config) GetProxyTLSConfig(_ ProxyAddr, _ VictimAddr) (*tls.Config, error) {
	return proxyTlsConfig, nil
}

func (c Config) GetProxyAddr() (ip string, port string, err error) {
	return "192.168.86.174", "10000", nil
}

func (c Config) GetDownstreamTLSConfig(_ ProxyAddr, _ VictimAddr) (*tls.Config, error) {
	return downstreamTlsConfig, nil
}

func (c Config) GetDownstreamAddr(_ ProxyAddr, _ VictimAddr) (ip string, port string, err error) {
	return "192.168.86.3", "10000", nil
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

func (c Config) HandleVictimData(b []byte, _ ConnInfo) {
	println("victim data", "--->", string(b))
}

func (c Config) HandleDownstreamData(b []byte, _ ConnInfo) {
	println("victim data", "--->", string(b))
}

func TestProxyServer_Serve(t *testing.T) {
	type fields struct {
		cfg Cfg
	}
	type args struct {
		ctx context.Context
	}

	ctx := context.TODO()
	//var cancel context.CancelFunc
	//ctx, cancel = context.WithTimeout(ctx, 30*time.Second)

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{name: "test", fields: fields{cfg: Config{}}, args: args{ctx: ctx}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ProxyServer{
				cfg: tt.fields.cfg,
			}
			if err := s.Serve(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	//cancel()
}
