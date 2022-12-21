package httplogger

import (
	"fmt"
	"golang.conradwood.net/go-easyops/utils"
	"os"
	"time"
)

type disklogger struct {
}

type disk_http_request struct {
	url     string
	id      uint64
	started time.Time
}

func (d *disklogger) RequestStarted(url string, peer string) HTTPRequest {
	res := &disk_http_request{
		url:     url,
		id:      getNextReqCtr(),
		started: time.Now(),
	}
	res.Printf("started for %s", url)
	return res
}
func (d *disk_http_request) RequestProgressed(msg string) {
}
func (d *disk_http_request) RequestFinished(httpcode uint32, backend string, msg string, err error) {
	es := ""
	if err != nil && httpcode != 404 {
		es = utils.ErrorString(err)
	}
	d.Printf("finished %d %s%s for %s", httpcode, msg, es, d.url)
}
func (d *disk_http_request) Printf(format string, args ...interface{}) {
	val := fmt.Sprintf(format, args...)
	s := time.Since(d.started).Seconds()
	l := fmt.Sprintf("[httplogger %02d %0.2fs] %s\n", d.id, s, val)
	f, err := os.OpenFile("/tmp/h2gproxy.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
	if err != nil {
		fmt.Printf("failed to open file: %s\n", err)
		return
	}
	f.WriteString(l)
	f.Close()
	//	fmt.Print(l)

}
