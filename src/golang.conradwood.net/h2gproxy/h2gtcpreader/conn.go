package h2gtcpreader

import (
	"net"
	"time"
)

func (hr *Hreader) Close() error {
	hr.Debugf("closing\n")
	return hr.orig_conn.Close()
}

func (hr *Hreader) oRead(b []byte) (int, error) {
	return hr.orig_conn.Read(b)
}
func (hr *Hreader) Write(b []byte) (int, error) {
	n, err := hr.orig_conn.Write(b)
	if err == nil {
		hr.Debugf("written %d bytes, no error\n", n)
	} else {
		hr.Debugf("written %d bytes, error=%s\n", n, err)
	}
	return n, err
}
func (hr *Hreader) LocalAddr() net.Addr {
	return hr.orig_conn.LocalAddr()
}

func (hr *Hreader) RemoteAddr() net.Addr {
	return hr.orig_conn.RemoteAddr()
}
func (hr *Hreader) SetDeadline(t time.Time) error {
	return hr.orig_conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (hr *Hreader) SetReadDeadline(t time.Time) error {
	return hr.orig_conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (hr *Hreader) SetWriteDeadline(t time.Time) error {
	return hr.orig_conn.SetWriteDeadline(t)
}
