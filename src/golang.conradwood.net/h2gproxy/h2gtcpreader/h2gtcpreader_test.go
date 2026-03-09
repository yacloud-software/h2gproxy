package h2gtcpreader

import (
	"net"
	"testing"
)

func TestReader(t *testing.T) {
}
func TestListener(t *testing.T) {
	var l net.Conn
	c := NewConn(l)
	c.Read(make([]byte, 10))
}
