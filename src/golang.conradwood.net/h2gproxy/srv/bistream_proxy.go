package srv

import (
	"context"
	pb "golang.conradwood.net/apis/h2gproxy"
	"google.golang.org/grpc"
	"io"
)

func BiStreamProxy(f *FProxy) {
	err := bistream_proxy_exe(f)
	if err != nil {
		f.Debugf("bistream proxy failed: %s\n", err)
	}
}

func stream_Handler(srv interface{}, stream grpc.ServerStream) error {
	panic("stream handler not implemented")
	return nil
}

// bit more high-level, give it service, rpc and it'll return a useful stream
func (g *grpc_conn) OpenStream(ctx context.Context, rpc string, with_client, with_server bool) (*client_stream, error) {
	service := g.service_name
	sd := &grpc.StreamDesc{
		StreamName:    rpc,
		Handler:       stream_Handler,
		ServerStreams: with_server,
		ClientStreams: with_client,
	}
	rpc_name := "/" + service + "/" + rpc
	cs, err := g.NewStream(ctx, sd, rpc_name)
	return cs, err
}

func bistream_proxy_exe(f *FProxy) error {
	_, err := f.GetForm()
	if err != nil {
		return err
	}

	auth_result, err := json_auth(f) // always check if we got auth stuff
	if err != nil {
		return err
	}

	svc := GetGRPCConnection(f.hf.def.TargetService)
	f.Debugf("service: %s\n", svc)
	ctx, err := createContext(f, auth_result)
	if err != nil {
		return err
	}
	defer svc.Close()

	stream, err := svc.OpenStream(ctx, "StreamBiHTTP", true, true)
	if err != nil {
		return err
	}
	defer stream.Finish()
	svc.Debugf("bistream proxy allocated new stream (%s)\n", stream)
	start := &pb.BiStreamRequest{HTTPRequest: &pb.StreamRequest{Path: "set-by-h2gproxy-request.path"}}
	err = stream.SendMsg(start)
	if err != nil {
		return err
	}

	err = stream.CloseSend()
	if err != nil {
		return err
	}

	msg := &pb.BiStreamResponse{}
	for {
		err := stream.RecvMsg(msg)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if msg.HTTPResponse != nil && msg.HTTPResponse.Filename != "" {
			svc.Debugf("receiving filename \"%s\"\n", msg.HTTPResponse.Filename)
		} else {
			svc.Debugf("message received: %s\n", msg)
		}
	}

	return nil
}
