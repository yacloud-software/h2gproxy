package h2gtcpreader

import (
	"io"
	"net"

	h2g "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
)

const (
	START_BYTE = 1
	END_BYTE   = 0
)

// this is an io.Reader and a net.Conn
type hreader struct {
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
func NewConn(l net.Conn) *hreader {
	l.LocalAddr() // test to see if nil
	return &hreader{is_conn: true, orig_conn: l, scan_for_header: true}
}

func NewReader(r io.Reader) *hreader {
	return &hreader{orig_reader: r, scan_for_header: true}
}

// block until we got header.
func (h *hreader) Read_Header() (*h2g.TCPStart, error) {
	if h.tcpstart != nil {
		return h.tcpstart, nil
	}
	buf := make([]byte, 16384)
	_, err := h.Read(buf)
	if err != nil {
		return nil, err
	}
	res := &h2g.TCPStart{}
	err = utils.Unmarshal(string(h.headerbuf), res)
	if err != nil {
		return nil, err
	}
	h.tcpstart = res
	return h.tcpstart, nil
}

// might return nil though
func (h *hreader) GetHeader() *h2g.TCPStart {
	if h.tcpstart != nil {
		return h.tcpstart
	}
	res := &h2g.TCPStart{}
	utils.Unmarshal(string(h.headerbuf), res)
	h.tcpstart = res
	return h.tcpstart
}

func (h *hreader) Read(buf []byte) (int, error) {
	if h.scan_for_header {
		err := h.read_header()
		if err != nil {
			return 0, err
		}
	}
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
func (h *hreader) read_header() error {
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
				continue
			}
			xbuf = mbuf[2 : n-2]
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

func (h *hreader) read_from_orig(buf []byte) (int, error) {
	if h.is_conn {
		return h.orig_conn.Read(buf)
	}
	return h.orig_reader.Read(buf)

}
