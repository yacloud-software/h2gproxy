package srv

import (
	"context"
	"fmt"
	"golang.conradwood.net/go-easyops/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"sync"
)

var (
	con            []*grpc_conn
	grpc_conn_lock sync.Mutex
)

type grpc_conn struct {
	Name           string
	Conn           *grpc.ClientConn
	stream_counter int
	failed         bool
	lock           sync.Mutex
}

func (g *grpc_conn) AvailableForNewStreams() bool {
	if g.failed {
		return false
	}
	if g.stream_counter > 3 {
		return false
	}
	return true
}
func GetGRPCConnection(name string) *grpc_conn {
	for _, c := range con {
		if c.Name == name && c.AvailableForNewStreams() {
			return c
		}
	}
	grpc_conn_lock.Lock()
	for _, c := range con {
		if c.Name == name && c.AvailableForNewStreams() {
			grpc_conn_lock.Unlock()
			return c
		}
	}
	grpc_conn_lock.Unlock()
	cc := client.Connect(name)
	res := &grpc_conn{Name: name, Conn: cc}

	grpc_conn_lock.Lock()
	for _, c := range con {
		if c.Name == name && c.AvailableForNewStreams() {
			grpc_conn_lock.Unlock()
			return c
		}
	}
	con = append(con, res)
	grpc_conn_lock.Unlock()
	return res
}
func (g *grpc_conn) streamCounterInc() {
	g.lock.Lock()
	g.stream_counter++
	g.lock.Unlock()
}
func (g *grpc_conn) streamCounterDec() {
	g.lock.Lock()
	if g.stream_counter == 0 {
		panic("grpc stream counter negative value")
	}
	g.stream_counter--
	g.lock.Unlock()
}
func (g *grpc_conn) NewStream(ctx context.Context, desc *grpc.StreamDesc, name string) (*client_stream, error) {
	gs, err := g.Conn.NewStream(ctx, desc, name)
	if err != nil {
		g.Debugf("could not open stream (%s)\n", err)
		return nil, err
	}
	g.streamCounterInc()
	g.Debugf("Opening stream #%d\n", g.stream_counter)
	cs := &client_stream{clientstream: gs, conn: g}
	return cs, nil
}

func (g *grpc_conn) Debugf(format string, args ...interface{}) {
	if !*debug {
		return
	}
	s := fmt.Sprintf(format, args...)
	fmt.Printf("[grpccon %s] %s", g.Name, s)
}
func (g *grpc_conn) Fail(err error) {
	g.failed = true
}

type client_stream struct {
	clientstream grpc.ClientStream
	conn         *grpc_conn
}

func (c *client_stream) Header() (metadata.MD, error) {
	return c.clientstream.Header()
}

func (c *client_stream) Trailer() metadata.MD {
	return c.clientstream.Trailer()
}
func (c *client_stream) CloseSend() error {
	return c.clientstream.CloseSend()
}
func (c *client_stream) Context() context.Context {
	return c.clientstream.Context()
}
func (c *client_stream) SendMsg(m interface{}) error {
	return c.clientstream.SendMsg(m)
}
func (c *client_stream) RecvMsg(m interface{}) error {
	return c.clientstream.RecvMsg(m)
}
func (c *client_stream) Finish() {
	c.conn.streamCounterDec()
}
func (c *client_stream) Fail(err error) {
	c.conn.Fail(err)
	c.Finish()
}
