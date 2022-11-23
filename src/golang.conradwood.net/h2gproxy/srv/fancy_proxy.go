package srv

import (
	"context"
	"fmt"
	lb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
	"google.golang.org/grpc"
	"io"
)

/*****************************
* fancy proxy ;)
*****************************/
type fancy_proxy struct {
	targetservice string
}

func FancyProxy(f *FProxy) {
	fmt.Printf("fancy proxying\n")
	wp := &fancy_proxy{targetservice: f.hf.def.TargetService}
	gp := NewStreamProxy(f, wp)
	gp.Proxy()
}

func (j *fancy_proxy) BackendStream(ctx context.Context, fcr *lb.StreamRequest, in_stream chan *lb.BodyData, out *lb.StreamResponse, out_stream chan *lb.BodyData) error {
	fmt.Printf("Fancyproxy to \"%s\"\n", j.targetservice)
	if *debug {
		fmt.Printf("[fancyproxy] - streaming %s\n", j.targetservice)
		fmt.Printf("[fancyproxy] in: %s\n", fcr.Path)
	}
	out.MimeType = "text/plain"

	// connect to your backend and start streaming from it
	cc := GetGRPCConnection(j.targetservice)
	stream, err := cc.NewStream(ctx,
		&grpc.StreamDesc{
			StreamName:    "BiStreamHTTP",
			Handler:       DownloadStreamHandler,
			ServerStreams: true,
			ClientStreams: true,
		},
		fmt.Sprintf("/%s/BiStreamHTTP", j.targetservice))
	if err != nil {
		return fmt.Errorf("newstream failed: %s", err)
	}
	if *debug {
		fmt.Printf("[fancyproxy] sending header to backend\n")
	}
	// send the header to backend
	sdr := &lb.StreamDataRequest{Request: fcr}
	if err := stream.SendMsg(sdr); err != nil {
		return fmt.Errorf("sendmsg1: %s", err)
	}
	if *debug {
		fmt.Printf("[fancyproxy] sending body to backend\n")
	}
	// send the body to backend:
	for {
		bd := <-in_stream
		if bd == nil {
			break
		}

		sdr = &lb.StreamDataRequest{Data: bd.Data}
		if err := stream.SendMsg(sdr); err != nil {
			return fmt.Errorf("sendmsg2: %s", err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}

	if *debug {
		fmt.Printf("[fancyproxy] retrieving response\n")
	}
	for {
		resp := &lb.StreamDataResponse{}
		// TODO: handle streamresponse here instead of only data
		err = stream.RecvMsg(resp)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("[fancyproxy] error encountered: %s\n", utils.ErrorString(err))
			return err
		}
		if resp.Response != nil {
			*out = *resp.Response
		}
		if len(resp.Data) > 0 {
			out_stream <- &lb.BodyData{Data: resp.Data}
		}
	}
	close(out_stream)
	if *debug {
		fmt.Printf("[fancyproxy] done\n")
	}

	return nil
}
