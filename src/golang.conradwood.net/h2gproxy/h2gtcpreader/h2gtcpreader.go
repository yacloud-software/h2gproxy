package h2gtcpreader

import (
	"bytes"
	"fmt"
	"io"
	"net"

	h2g "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
)

const (
	START_BYTE = 1
	END_BYTE   = 0
)

var (
	debug = utils.DebugFlag("h2gproxy_tcp_header")
)

// this is an io.Reader and a net.Conn
type Hreader struct {
	is_conn          bool
	orig_reader      io.Reader
	orig_conn        net.Conn
	scan_for_header  bool
	pos_is_in_header bool
	headerbuf        []byte // this is the header
	bytes_for_reader []byte // these bytes must go to the reader
	tcpstart         *h2g.TCPStart
}

// wrap a net.Conn
func NewConn(l net.Conn) *Hreader {
	l.LocalAddr() // test to see if nil
	return &Hreader{is_conn: true, orig_conn: l, scan_for_header: true}
}

func NewReader(r io.Reader) *Hreader {
	return &Hreader{orig_reader: r, scan_for_header: true}
}

// block until we got header.
func (h *Hreader) ReadHeader() (*h2g.TCPStart, error) {
	if h.tcpstart != nil {
		return h.tcpstart, nil
	}
	h.Debugf("Reading header\n")
	buf, err := h.read_until_header_end_byte()
	if err != nil {
		return nil, err
	}
	buf = buf[:len(buf)-1] // remove end_byte
	buf = buf[2:]          // remove start_byte+version
	h.Debugf("%s\n", utils.Hexdump("header bytes ", buf))
	res := &h2g.TCPStart{}
	err = utils.Unmarshal(string(buf), res)
	if err != nil {
		fmt.Print(utils.Hexdump("broken header ", h.headerbuf))
		return nil, err
	}
	h.Debugf("Got Header\n")
	h.tcpstart = res
	return h.tcpstart, nil
}

// return header including start and end byte
func (h *Hreader) read_until_header_end_byte() ([]byte, error) {
	buf := make([]byte, 8192)
	var res []byte
	for {
		n, err := h.read_from_orig(buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		// contains end-byte?
		if len(res) > 0 {
			if res[0] != START_BYTE {
				h.inject_for_read(res)
				h.inject_for_read(buf[:n])
				res = nil
				break
			}
		}
		res = append(res, buf[:n]...)
		h.Debugf("%d bytes read, %s", n, utils.Hexdump("curbuf: ", res))
		// TODO-only check new bytes for endbyte
		idx := bytes.Index(res, []byte{END_BYTE})
		if idx == -1 {
			h.Debugf("no endbyte (%d) yet\n", END_BYTE)
			// no endbyte yet, keep reading
			continue
		}
		h.Debugf("got endpoint at position %d\n", idx)
		add_buf := res[idx+1:]
		res = res[:idx+1]
		h.inject_for_read(add_buf)
		break
	}
	return res, nil
}

func (h *Hreader) inject_for_read(buf []byte) {
	h.bytes_for_reader = append(h.bytes_for_reader, buf...)
}

// might return nil though
func (h *Hreader) GetHeader() *h2g.TCPStart {
	if h.tcpstart != nil {
		return h.tcpstart
	}
	res := &h2g.TCPStart{}
	utils.Unmarshal(string(h.headerbuf), res)
	h.tcpstart = res
	return h.tcpstart
}

func (h *Hreader) Read(buf []byte) (int, error) {
	if len(h.bytes_for_reader) > 0 {
		for i := 0; i < len(buf); i++ {
			if i >= len(h.bytes_for_reader) {
				h.bytes_for_reader = nil
				return i, nil
			}
			buf[i] = h.bytes_for_reader[i]
		}
		h.bytes_for_reader = h.bytes_for_reader[len(buf):]
		return len(buf), nil
	}
	return h.read_from_orig(buf)
}

// return bytes to send to reader
func (h *Hreader) read_header() error {
	mbuf := make([]byte, 8192)
	first_round := true
	var xbuf []byte
	for {
		n, err := h.read_from_orig(mbuf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if first_round {
			first_round = false
			if mbuf[0] != START_BYTE { // start-byte?
				// no header at all
				h.bytes_for_reader = append(h.bytes_for_reader, mbuf[:n]...)
				return err
			}

			if n <= 2 {
				h.Debugf("WARNING - short read (%d bytes)\n", n)
				continue
			}

			xbuf = mbuf[2 : n-2] // skip start-byte and version
			if debug.BoolValue() {
				fmt.Println(utils.Hexdump("read: ", mbuf[:n]))
				fmt.Println(utils.Hexdump("xbuf: ", xbuf))
			}
		} else {
			xbuf = mbuf[:n]
		}

		// split xbuf into header & bytestosend
		endbyte_at := -1
		for i, b := range xbuf {
			if b == END_BYTE {
				endbyte_at = i
				break
			}
		}
		if endbyte_at == -1 {
			h.headerbuf = append(h.headerbuf, xbuf...)
		} else {
			h.headerbuf = append(h.headerbuf, xbuf[:endbyte_at]...)
			h.bytes_for_reader = append(h.bytes_for_reader, xbuf[endbyte_at+1:]...)
			h.scan_for_header = false
			return err
		}

	}
}

func (h *Hreader) read_from_orig(buf []byte) (int, error) {
	var n int
	var err error
	if h.is_conn {
		n, err = h.orig_conn.Read(buf)
	} else {
		n, err = h.orig_reader.Read(buf)
	}
	if err == nil {
		h.Debugf("read %d bytes, no error\n", n)
	} else {
		h.Debugf("read %d bytes, error=%s\n", n, err)
	}
	return n, err

}

func (h *Hreader) Debugf(format string, args ...any) {
	if !debug.BoolValue() {
		return
	}
	extra := "-no header yet-"
	if h.tcpstart != nil {
		extra = fmt.Sprintf("%s:%d", h.tcpstart.RemoteIP, h.tcpstart.RemotePort)
	}
	prefix := fmt.Sprintf("[h2gtcpreader %s] ", extra)
	x := fmt.Sprintf(format, args...)
	fmt.Print(prefix + x)
}
