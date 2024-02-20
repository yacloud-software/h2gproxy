package httplogger

import (
	"flag"
	"fmt"
)

var (
	default_logger = flag.String("logger", "", "[disk|noop], default empty (noop)")
)

type HTTPLogger interface {
	RequestStarted(url string, peer string) HTTPRequest
}
type HTTPRequest interface {
	RequestProgressed(msg string)
	RequestFinished(httpcode uint32, backend string, msg string, err error)
}

func DefaultHTTPLogger() HTTPLogger {
	ul := *default_logger
	if ul == "" {
		ul = "noop"
	}
	if ul == "disk" {
		return &disklogger{}
	} else if ul == "noop" {
		return &nooplogger{}
	}
	fmt.Printf("UNKNOWN LOGGER \"%s\"\n", ul)
	return &nooplogger{}

}
