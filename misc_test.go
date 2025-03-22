package gosplit

import (
	"crypto/x509/pkix"
	"net"
	"testing"
)

func TestGenSelfSignedCert(t *testing.T) {
	type args struct {
		subject  pkix.Name
		ips      []net.IP
		dnsNames []string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{name: "test", args: args{
			subject:  pkix.Name{Organization: []string{"Test Org"}},
			ips:      []net.IP{net.ParseIP("127.0.0.1")},
			dnsNames: []string{"localhost"},
		}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenSelfSignedCert(tt.args.subject, tt.args.ips, tt.args.dnsNames)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenSelfSignedCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
