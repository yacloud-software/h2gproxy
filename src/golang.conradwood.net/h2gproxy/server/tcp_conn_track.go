package main

import (
	"context"
	"fmt"
	"golang.conradwood.net/apis/common"
	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/errors"
	"net"
	"sync"
)

var (
	tcplock         sync.Mutex
	tcp_connections []*TCPProxySession
)

/********************************************************************************
* the proxy session
********************************************************************************/

type TCPProxySession struct {
	forwarder *TCPForwarder
	inbound   *TCPConnection
	outbound  *TCPConnection
}

func newTCPProxySession(tf *TCPForwarder, c1, c2 net.Conn) *TCPProxySession {
	tc := &TCPProxySession{forwarder: tf, inbound: &TCPConnection{con: c1}, outbound: &TCPConnection{con: c2}}
	tcplock.Lock()
	tcp_connections = append(tcp_connections, tc)
	tcplock.Unlock()
	if *debug_tcp {
		fmt.Printf("New Connection: %s\n", tc.ConnectionString())
	}
	return tc
}
func (t *TCPProxySession) Closed() {
	if *debug_tcp {
		fmt.Printf("Closed Connection: %s\n", t.ConnectionString())
	}
	var n []*TCPProxySession
	tcplock.Lock()
	for _, tt := range tcp_connections {
		if tt == t {
			continue
		}
		n = append(n, tt)
	}
	tcp_connections = n
	tcplock.Unlock()
}
func (t *TCPProxySession) ConnectionString() string {
	return fmt.Sprintf("%s <=> %s", t.inbound.String(), t.outbound.String())
}
func (t *TCPProxySession) Session() *pb.TCPSession {
	ts := &pb.TCPSession{
		InboundPort: uint32(t.forwarder.Port),
		Config:      t.forwarder.session,
	}
	_, ts.ProxyOutboundPort = t.outbound.LocalAddr()
	ts.ProxyTargetHost, ts.ProxyTargetPort = t.outbound.RemoteAddr()
	ts.PeerHost, ts.PeerPort = t.inbound.RemoteAddr()
	return ts
}

/********************************************************************************
* one connection of the proxy-session (a proxy has two connections)
********************************************************************************/

type TCPConnection struct {
	con net.Conn
}

func (t *TCPConnection) LocalAddr() (string, uint32) {
	ad := t.con.LocalAddr()
	iad := ad.(*net.TCPAddr)
	return iad.IP.String(), uint32(iad.Port)
}
func (t *TCPConnection) RemoteAddr() (string, uint32) {
	ad := t.con.RemoteAddr()
	iad := ad.(*net.TCPAddr)
	return iad.IP.String(), uint32(iad.Port)
}
func (t *TCPConnection) String() string {
	la, lp := t.LocalAddr()
	ra, rp := t.RemoteAddr()
	return fmt.Sprintf("%s:%d-%s:%d", la, lp, ra, rp)
}

/********************************************************************************
* the grpc stuff
********************************************************************************/

func (*H2gproxyServer) GetTCPMeta(ctx context.Context, req *pb.TCPMetaRequest) (*pb.TCPSession, error) {
	for _, t := range tcp_connections {
		// this match isn't good enough. textual comparison doesn't cut it.
		// it may be different IPs, Nat, Hostnames, foo...
		la, lp := t.outbound.LocalAddr()
		if la != req.ProxyOutboundHost || lp != req.ProxyOutboundPort {
			continue
		}
		ra, rp := t.outbound.RemoteAddr()
		if req.ProxyTargetHost != "" && ra != req.ProxyTargetHost {
			continue
		}
		if req.ProxyTargetPort != 0 && rp != req.ProxyTargetPort {
			continue
		}
		return t.Session(), nil
	}
	return nil, errors.NotFound(ctx, "no such connection (%s:%d / %s:%d", req.ProxyOutboundHost, req.ProxyOutboundPort, req.ProxyTargetHost, req.ProxyTargetPort)
}
func (*H2gproxyServer) GetTCPSessions(ctx context.Context, req *common.Void) (*pb.TCPSessionList, error) {
	res := &pb.TCPSessionList{}
	for _, t := range tcp_connections {
		res.Sessions = append(res.Sessions, t.Session())
	}
	return res, nil
}
