package gosplit

import (
	"context"
	"crypto/x509/pkix"
	"net"
	"testing"
)

func TestGenSelfSignedCert(t *testing.T) {
	type args struct {
		subject  pkix.Name
		ips      []net.IP
		dnsNames []string
		priv     *RSAPrivKey
	}
	argVals := args{
		subject:  pkix.Name{Organization: []string{"Test Org"}},
		ips:      []net.IP{net.ParseIP("127.0.0.1")},
		dnsNames: []string{"localhost"},
	}
	argV2 := argVals
	if argV2.priv = NewRSAPrivKey(100); argV2.priv.Err() != nil {
		t.Errorf("NewRSAPrivKey() failed: %v", argV2.priv.Err())
		return
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "random private key", args: argVals, wantErr: false},
		{name: "with private key", args: argVals, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenSelfSignedCert(tt.args.subject, tt.args.ips, tt.args.dnsNames, tt.args.priv)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenSelfSignedCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRSAPrivKeyGenerator(t *testing.T) {
	type args struct {
		ctx    context.Context
		bitLen int
	}

	tests := []struct {
		name    string
		args    args
		wantC   chan *RSAPrivKey
		wantErr bool
	}{
		{name: "0 bit length", args: args{bitLen: 0}, wantC: make(chan *RSAPrivKey), wantErr: true},
		{name: "-1 bit length", args: args{bitLen: -1}, wantC: make(chan *RSAPrivKey), wantErr: true},
		{name: "512 bit length", args: args{bitLen: 512}, wantC: make(chan *RSAPrivKey), wantErr: false},
		{name: "1024 bit length", args: args{bitLen: 1024}, wantC: make(chan *RSAPrivKey), wantErr: false},
		{name: "2048 bit length", args: args{bitLen: 2048}, wantC: make(chan *RSAPrivKey), wantErr: false},
	}

	for _, tt := range tests {
		var cancel context.CancelFunc
		tt.args.ctx, cancel = context.WithCancel(context.Background())
		t.Run(tt.name, func(t *testing.T) {
			gotC, err := StartRSAPrivKeyGenerator(tt.args.ctx, tt.args.bitLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("StartRSAPrivKeyGenerator() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil {
				for i := 0; i < 5; i++ {
					k := <-gotC
					if k.Err() != nil {
						t.Errorf("StartRSAPrivKeyGenerator() gotC = %v, want %v", k.Err(), tt.wantErr)
						return
					}
				}
			}
		})
		cancel()
	}
}
