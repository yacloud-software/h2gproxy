package srv

import (
	"flag"
	"fmt"

	"golang.conradwood.net/apis/antidos"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/shared"
)

var (
	enable_backend_failure_handling = flag.Bool("enable_backend_failure_reporting", true, "tell antidos every time backend fails")
)

// handle a backend_failure
func backend_failure(f *FProxy, err error) {
	if err == nil {
		return
	}
	if !*enable_backend_failure_handling {
		return
	}
	if f.GetUser() != nil {
		return
	}
	h_code := uint32(shared.ConvertErrorToCode(err))
	req := &antidos.HTTPReport{
		Host:          f.RequestedHost(),
		Path:          f.RequestedPath(),
		IP:            f.PeerIP(),
		HTTPErrorCode: h_code,
		Message:       utils.ErrorString(err),
		BackendType:   f.hf.ApiTypeName(),
		Backend:       f.hf.def.ConfigName,
	}
	ctx := authremote.Context()
	_, err = antidos.GetAntiDOSClient().IPReportHTTP(ctx, req)
	if err != nil {
		fmt.Printf("Failed to inform antidos client: %s\n", utils.ErrorString(err))
	}
}
