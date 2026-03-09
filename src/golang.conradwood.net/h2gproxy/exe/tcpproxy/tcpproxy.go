package tcpproxy

import (
	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/errors"
)

func NewTCPForwarder(cr *h2gproxy.AddConfigTCPRequest) (*TCPForwarder, error) {
	res := &TCPForwarder{Port: int(cr.SourcePort), Path: cr.TargetServicePath, config: cr}
	if cr.EnableTLS {
		if cr.TLSSubject == "" {
			return nil, errors.Errorf("TCP forwarder on port %d has tls enabled, but does not defined tls subject. missing \"tlssubject\" option", res.Port)
		}
	}
	return res, nil
}
