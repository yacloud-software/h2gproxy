package grpchelpers

import (
	"context"
	"flag"
	"fmt"
	"sync"

	"golang.conradwood.net/go-easyops/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var (
	debug          = flag.Bool("debug_grpcconnections", false, "debug grpc connection cache")
	reuse_after    = flag.Int("max_streams_for_con", 0, "if non zero, reconnect to target after a stream has served this many streams")
	con            []*grpc_conn
	grpc_conn_lock sync.Mutex
)

type ClientStream interface {
	Fail(error)
	Finish()
	CloseSend() error
	RecvMsg(m interface{}) error
	SendMsg(m interface{}) error
}
type GRPCConnection interface {
	OpenStream(ctx context.Context, rpc string, with_client, with_server bool) (ClientStream, error)
	NewStream(ctx context.Context, desc *grpc.StreamDesc, name string) (ClientStream, error)
	String() string
	Close()
}

type grpc_conn struct {
	service_name         string
	Conn                 *grpc.ClientConn
	stream_counter       int //currently open streams
	total_stream_counter int // total opened
	opened               int // how many peeps use this connection (one might have a connection with 0 or 2+ streams)
	failed               bool
	lock                 sync.Mutex
}

func (g *grpc_conn) String() string {
	return fmt.Sprintf("grpc-con to \"%s\" (%d open)", g.service_name, g.opened)
}

func (g *grpc_conn) AvailableForNewStreams() bool {
	if *reuse_after == 0 {
		return true
	}
	if g.failed {
		return false
	}
	if g.stream_counter > *reuse_after {
		return false
	}
	return true
}

// given a servicename will return a grpc connection (which must be closed after use!)
func GetGRPCConnection(name string) GRPCConnection {
	if *debug {
		fmt.Printf("[grpc-con] (1) Got %d connections\n", len(con))
	}
	grpc_closer()
	if *debug {
		fmt.Printf("[grpc-con] (2) Got %d connections\n", len(con))
	}
	for _, c := range con {
		if c.service_name == name && c.AvailableForNewStreams() {
			grpc_conn_lock.Lock()
			c.opened++
			grpc_conn_lock.Unlock()
			return c
		}
	}
	grpc_conn_lock.Lock()
	for _, c := range con {
		if c.service_name == name && c.AvailableForNewStreams() {
			c.opened++
			grpc_conn_lock.Unlock()
			return c
		}
	}
	grpc_conn_lock.Unlock()
	cc := client.Connect(name)
	res := &grpc_conn{service_name: name, Conn: cc}

	grpc_conn_lock.Lock()
	for _, c := range con {
		if c.service_name == name && c.AvailableForNewStreams() {
			c.opened++
			grpc_conn_lock.Unlock()
			return c
		}
	}
	con = append(con, res)
	res.opened++
	grpc_conn_lock.Unlock()
	return res
}

func (g *grpc_conn) Close() {
	grpc_conn_lock.Lock()
	if g.opened == 0 {
		panic("g.opened < 0!")
	}
	g.opened--
	grpc_conn_lock.Unlock()
}
func (g *grpc_conn) streamCounterInc() {
	g.lock.Lock()
	g.stream_counter++
	g.total_stream_counter++
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

// bit more high-level, give it service, rpc and it'll return a useful stream
func (g *grpc_conn) OpenStream(ctx context.Context, rpc string, with_client, with_server bool) (ClientStream, error) {
	service := g.service_name
	sd := &grpc.StreamDesc{
		StreamName:    rpc,
		Handler:       stream_Handler,
		ServerStreams: with_server,
		ClientStreams: with_client,
	}
	rpc_name := "/" + service + "/" + rpc
	cs, err := g.NewStream(ctx, sd, rpc_name)
	return cs, err
}

/*
You probably want OpenStream() instead!
"name" is the rpc name including service, e.g. "/httpdebug.HTTPDebug/StreamBiHTTP"
"streamdesc" is ...
*/
func (g *grpc_conn) NewStream(ctx context.Context, desc *grpc.StreamDesc, name string) (ClientStream, error) {
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
	fmt.Printf("[grpccon %s] %s", g.service_name, s)
}
func (g *grpc_conn) Fail(err error) {
	g.failed = true
}

type client_stream struct {
	clientstream grpc.ClientStream
	conn         *grpc_conn
}

func (c *client_stream) String() string {
	return fmt.Sprintf("stream for \"%s\"", c.conn.service_name)
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
func grpc_closer() {
	if *reuse_after == 0 {
		return
	}
	grpc_conn_lock.Lock()
	var res []*grpc_conn
	var closing []*grpc_conn
	for _, c := range con {
		remove := false
		if c.failed && c.opened == 0 {
			remove = true
		}
		if c.total_stream_counter > *reuse_after && c.opened == 0 {
			remove = true
		}
		if remove {
			closing = append(closing, c)
		} else {
			res = append(res, c)
		}
	}
	for _, c := range closing {
		c.failed = true
	}
	con = res
	grpc_conn_lock.Unlock()

	// slow(er) - outside the lock
	for _, c := range closing {
		c.Conn.Close()
		c.Conn = nil
		c.failed = true
	}

}

func stream_Handler(srv interface{}, stream grpc.ServerStream) error {
	panic("stream handler not implemented")
}
