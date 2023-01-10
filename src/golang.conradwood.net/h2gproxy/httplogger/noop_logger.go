package httplogger


type nooplogger struct {
}

type noop_http_request struct {
}

func (d *nooplogger) RequestStarted(url string, peer string) HTTPRequest {
	res := &noop_http_request{}
	return res
}
func (d *noop_http_request) RequestProgressed(msg string) {
}
func (d *noop_http_request) RequestFinished(httpcode uint32, backend string, msg string, err error) {
}
func (d *noop_http_request) Printf(format string, args ...interface{}) {
}
