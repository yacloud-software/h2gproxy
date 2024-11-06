package stream

import (
	"context"

	"golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/h2gproxy"
)

type RequestDetails interface {
	TargetService() string
	UserContext() (context.Context, context.CancelFunc)
	BootstrapContext() context.Context
	SetContentLength(size uint64)
	SetFilename(name string)
	SetContentType(mimetype string)
	SetStatus(code int) // http error code
	SetHeader(key, value string)
	Write(buf []byte) error
	RequestedPath() string
	PeerIP() string
	GetUser() *auth.User // might be nil
	UserAgent() string
	RequestedQuery() string
	RequestedHost() string
	RequestBody() []byte
	RequestValues() map[string]string
	RequestHeaders() map[string]string
	H2GHeaders() []*h2gproxy.Header
	H2GParameters() []*h2gproxy.Parameter
	ByteRanges() []*h2gproxy.ByteRange
	TriggerAuthentication() // send response that after a 401 the request needs to be retried with authentication
	NeedsAuth() bool        // true if request must be authenticated prior to calling a backend
}
