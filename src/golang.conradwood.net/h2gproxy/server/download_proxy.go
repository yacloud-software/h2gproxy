package main

import (
	"context"
	"fmt"
	lb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
	rl "golang.conradwood.net/h2gproxy/ratelimiter"
	"google.golang.org/grpc"
	"io"
	"time"
	//"golang.conradwood.net/apis/create"
)

var (
	rlimiter = rl.NewLimiter()
)

/*****************************
* streaming download proxy
*****************************/

type download_proxy struct {
	targetservice string
}

func DownloadProxy(f *FProxy) {
	// simple DoS protection. allow max 3 clients
	// the golang HTTP and TCP stack buffer, as well as the linux
	// kernel TCP stack, so this isn't 100% accurate, but it feels
	// better than having no resource limit in place at all
	if !rlimiter.RequestStart() {
		if *debug {
			fmt.Printf("too many clients\n")
		}
		f.SetStatus(429)
		return
	}
	defer rlimiter.RequestFinish()
	wp := &download_proxy{targetservice: f.hf.def.TargetService}
	gp := NewStreamProxy(f, wp)
	gp.Proxy()

}

func (j *download_proxy) ExampleBidirectional(ctx context.Context, in *lb.StreamRequest, in_stream chan *lb.BodyData, out *lb.StreamResponse, out_stream chan *lb.BodyData) error {
	if *debug {
		fmt.Printf("[downloadproxy] - streaming %s\n", j.targetservice)
		fmt.Printf("[downloadproxy] in: %s\n", in.Path)
		fmt.Printf("[downloadproxy] Reading stream...\n")
	}
	for {
		b, finished := <-in_stream
		l := 0
		if b != nil {
			l = len(b.Data)
		}
		fmt.Printf("[downloadproxy] Received %d bytes (%v)\n", l, finished)
		if !finished {
			break
		}
	}
	out.MimeType = "text/plain"
	for i := 0; i < 5; i++ {
		out_stream <- &lb.BodyData{Data: []byte("plaintext message\n")}
		time.Sleep(1 * time.Second)
	}
	close(out_stream)
	if *debug {
		fmt.Printf("[downloadproxy] done\n")
	}
	return nil
}

func (j *download_proxy) BackendStream(ctx context.Context, fcr *lb.StreamRequest, in_stream chan *lb.BodyData, out *lb.StreamResponse, out_stream chan *lb.BodyData) error {
	if *debug {
		fmt.Printf("[downloadproxy] - streaming %s\n", j.targetservice)
		fmt.Printf("[downloadproxy] in: %s\n", fcr.Path)
	}
	out.MimeType = "text/plain"

	// connect to your backend and start streaming from it
	cc := GetGRPCConnection(j.targetservice)
	stream, err := cc.NewStream(ctx,
		&grpc.StreamDesc{
			StreamName:    "StreamHTTP",
			Handler:       DownloadStreamHandler,
			ServerStreams: true,
		},
		fmt.Sprintf("/%s/StreamHTTP", j.targetservice))
	if err != nil {
		return err
	}
	if err := stream.SendMsg(fcr); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}

	for {
		resp := &lb.StreamDataResponse{}
		// TODO: handle streamresponse here instead of only data
		err = stream.RecvMsg(resp)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("[downloadproxy] error encountered: %s\n", utils.ErrorString(err))
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
		fmt.Printf("[downloadproxy] done\n")
	}
	return nil
}

func DownloadStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	return nil
}
