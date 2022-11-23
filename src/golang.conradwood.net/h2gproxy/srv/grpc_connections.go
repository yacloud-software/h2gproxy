package srv

import (
	"golang.conradwood.net/go-easyops/client"
	"google.golang.org/grpc"
	"sync"
)

var (
	con            []*grpc_conn
	grpc_conn_lock sync.Mutex
)

type grpc_conn struct {
	Name string
	Conn *grpc.ClientConn
}

func GetGRPCConnection(name string) *grpc.ClientConn {
	for _, c := range con {
		if c.Name == name {
			return c.Conn
		}
	}
	grpc_conn_lock.Lock()
	for _, c := range con {
		if c.Name == name {
			grpc_conn_lock.Unlock()
			return c.Conn
		}
	}
	grpc_conn_lock.Unlock()
	cc := client.Connect(name)
	res := &grpc_conn{Name: name, Conn: cc}

	grpc_conn_lock.Lock()
	for _, c := range con {
		if c.Name == name {
			grpc_conn_lock.Unlock()
			return c.Conn
		}
	}
	con = append(con, res)
	grpc_conn_lock.Unlock()
	return res.Conn
}
