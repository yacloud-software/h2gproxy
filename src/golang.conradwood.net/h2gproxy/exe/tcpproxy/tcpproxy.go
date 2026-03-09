package tcpproxy

import (
	"golang.conradwood.net/apis/h2gproxy"
)

func NewTCPForwarder(cr *h2gproxy.AddConfigTCPRequest) (*TCPForwarder, error) {
	res := &TCPForwarder{Port: int(cr.SourcePort), Path: cr.TargetServicePath, config: cr}
	return res, nil
}
