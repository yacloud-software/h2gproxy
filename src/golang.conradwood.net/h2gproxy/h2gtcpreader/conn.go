package h2gtcpreader

import (
	"net"
	"time"
)

func (hr *hreader) Close() error {
	return hr.orig_conn.Close()
}

func (hr *hreader) oRead(b []byte) (n int, err error) {
	return hr.orig_conn.Read(b)
}
func (hr *hreader) Write(b []byte) (n int, err error) {
	return hr.orig_conn.Write(b)
}
func (hr *hreader) LocalAddr() net.Addr {
	return hr.orig_conn.LocalAddr()
}

func (hr *hreader) RemoteAddr() net.Addr {
	return hr.orig_conn.RemoteAddr()
}
func (hr *hreader) SetDeadline(t time.Time) error {
	return hr.orig_conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (hr *hreader) SetReadDeadline(t time.Time) error {
	return hr.orig_conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (hr *hreader) SetWriteDeadline(t time.Time) error {
	return hr.orig_conn.SetWriteDeadline(t)
}
