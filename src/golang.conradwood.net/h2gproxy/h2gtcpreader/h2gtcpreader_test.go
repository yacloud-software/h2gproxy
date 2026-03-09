package h2gtcpreader

import (
	"bytes"
	"io"
	"testing"

	"golang.conradwood.net/go-easyops/utils"
)

func TestReader(t *testing.T) {
	check_if_header(t, []byte{1, 1, 50, 51, 52, 0, 10, 13})
}
func TestListener(t *testing.T) {
}

func check_if_header(t *testing.T, input_buf []byte) {
	r := bytes.NewReader(input_buf)
	xr := NewReader(r)
	buf, err := xr.read_until_header_end_byte()
	//h, err := xr.ReadHeader()
	if err != nil {
		t.Logf("buf: %s => error: %s\n", utils.HexStr(buf), err)
		t.Fail()
	}
	idx := bytes.Index(buf, []byte{END_BYTE})
	if idx != len(buf)-1 {
		t.Logf("input buf: %s\n", utils.HexStr(input_buf))
		t.Logf("headerbuf: %s\n", utils.HexStr(buf))
		t.Logf("idx=%d, header_len=%d\n", idx, len(buf))
		t.Fail()
	}
	t.Logf("Header: %v\n", utils.HexStr(buf))
	buf, err = io.ReadAll(xr)
	if err != nil {
		t.Logf("Failed to read remainder: %s\n", err)
		t.Fail()
	}
	t.Logf("remainder: %s\n", utils.HexStr(buf))
}
