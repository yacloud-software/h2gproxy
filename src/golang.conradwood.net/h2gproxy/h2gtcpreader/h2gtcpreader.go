package h2gtcpreader

import (
	h2g "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
	"io"
)

const (
	START_BYTE = 1
	END_BYTE   = 0
)

type hreader struct {
	orig             io.Reader
	scan_for_header  bool
	pos_is_in_header bool
	headerbuf        []byte // this is the header
	bytes_for_reader []byte // these bytes must go to the reader
	tcpstart         *h2g.TCPStart
}

func New(r io.Reader) *hreader {
	return &hreader{orig: r, scan_for_header: true}
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
	return h.orig.Read(buf)

}

// return bytes to send to reader
func (h *hreader) read_header() error {
	mbuf := make([]byte, 8192)
	first_round := true
	var xbuf []byte
	for {
		n, err := h.orig.Read(mbuf)
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
