package srv

import (
	"context"
	"golang.conradwood.net/apis/common"
	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/h2gproxy/probe"
)

//html
func (h *H2gproxyServer) ServeHTML(ctx context.Context, req *pb.ServeRequest) (*pb.ServeResponse, error) {
	if !*activate_probe_backend && !*run_probes {
		return nil, errors.FailedPrecondition(ctx, "prober backend deactivated")
	}
	return probe.ServeHTML(ctx, req)
}

//download
func (h *H2gproxyServer) BiStreamHTTP(srv pb.H2GProxyService_BiStreamHTTPServer) error {
	return errors.NotImplemented(srv.Context(), "bistream http not implemented")
}
func (h *H2gproxyServer) StreamHTTP(req *pb.StreamRequest, srv pb.H2GProxyService_StreamHTTPServer) error {
	if !*activate_probe_backend && !*run_probes {
		return errors.FailedPrecondition(srv.Context(), "prober backend deactivated")
	}
	return probe.StreamHTTP(req, srv)
}

// json
func (h *H2gproxyServer) Serve(ctx context.Context, req *pb.ServeRequest) (*pb.ServeResponse, error) {
	if !*activate_probe_backend && !*run_probes {
		return nil, errors.FailedPrecondition(ctx, "prober backend deactivated")
	}
	return probe.Serve(ctx, req)
}

// switch on/off
func (h *H2gproxyServer) ConfigureProber(ctx context.Context, req *pb.ConfigureProberRequest) (*common.Void, error) {
	err := errors.NeedsRoot(ctx)
	if err != nil {
		return nil, err
	}
	if req.ProberBackend {
		probe.StartHTTPBackend()
		*activate_probe_backend = true
	} else {
		probe.StopHTTPBackend()
		*activate_probe_backend = false
	}
	return &common.Void{}, nil
}
