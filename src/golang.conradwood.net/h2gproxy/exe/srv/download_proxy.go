package srv

import (
	"context"
	"fmt"
	"io"
	"time"

	lb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
	rl "golang.conradwood.net/h2gproxy/ratelimiter"
	"google.golang.org/grpc"
)

var (
	rlimiter = rl.NewLimiter()
)

/*****************************
* streaming download proxy
*
* apitype: download
*
*****************************/

type download_proxy struct {
	f             *FProxy
	targetservice string
}

func DownloadProxy(f *FProxy) {
	// simple DoS protection. allow max 3 clients
	// the golang HTTP and TCP stack buffer, as well as the linux
	// kernel TCP stack, so this isn't 100% accurate, but it feels
	// better than having no resource limit in place at all
	if !rlimiter.RequestStart() {
		fmt.Printf("too many clients (%s)\n", rlimiter.Status())
		f.SetAndLogFailure(429, fmt.Errorf("too many clients (%s)", rlimiter.Status()))
		return
	}
	defer rlimiter.RequestFinish()
	wp := &download_proxy{f: f, targetservice: f.hf.def.TargetService}
	gp := NewStreamProxy(f, wp)
	gp.Proxy()

}

func (j *download_proxy) BackendStream(ctx context.Context, fcr *lb.StreamRequest, out_stream chan *lb.BodyData) error {
	if *debug {
		fmt.Printf("[downloadproxy] - streaming %s\n", j.targetservice)
		fmt.Printf("[downloadproxy] in: %s\n", fcr.Path)
	}
	// connect to your backend and start streaming from it
	t := j.f.AddTiming("open_grpc_connection")
	cc := GetGRPCConnection(j.targetservice)
	t.Done()
	defer cc.Close()
	t = j.f.AddTiming("open_grpc_stream")
	stream, err := cc.NewStream(ctx,
		&grpc.StreamDesc{
			StreamName:    "StreamHTTP",
			Handler:       DownloadStreamHandler,
			ServerStreams: true,
			//ClientStreams: true, // gives a protocol violation thing
		},
		fmt.Sprintf("/%s/StreamHTTP", j.targetservice))
	if err != nil {
		return err
	}
	t.Done()
	t = j.f.AddTiming("startsend")
	if err := stream.SendMsg(fcr); err != nil {
		backend_failure(j.f, err)
		stream.Fail(err)
		return err
	}
	if err := stream.CloseSend(); err != nil {
		backend_failure(j.f, err)
		stream.Fail(err)
		return err
	}
	if *debug {
		fmt.Printf("[downloadproxy] - starting recv() loop\n")
	}
	t.Done()
	t = j.f.AddTiming("backend")
	sent := 0
	keep_running := true
	for keep_running {
		resp := &lb.StreamDataResponse{}
		// TODO: handle streamresponse here instead of only data
		err = stream.RecvMsg(resp)
		if err == io.EOF {
			break
		}
		if err != nil {
			backend_failure(j.f, err)
			fmt.Printf("[downloadproxy] error encountered: %s\n", utils.ErrorString(err))
			t.Done()
			stream.Fail(err)
			return err
		}
		if resp.Response != nil {
			if *debug {
				fmt.Printf("[downloadproxy] backend send response, requests statuscode=%d\n", resp.Response.StatusCode)
			}
		}
		sent++
		try_send_start := time.Now()
		repeat_send := true
		for keep_running && repeat_send {
			select {
			case out_stream <- &lb.BodyData{Response: resp}:
				repeat_send = false
				//
			case <-time.After(time.Duration(1) * time.Second):
				//
				if ctx.Err() != nil {
					keep_running = false
				}
				if time.Since(try_send_start) > time.Duration(60)*time.Second {
					// not a single packet got through for a long time: abort
					keep_running = false
				}
			}
		}

	}
	if *debug {
		fmt.Printf("[downloadproxy] sent %d objects to outchannel (backend->browser)\n", sent)
	}
	stream.Finish()
	t.Done()
	close(out_stream)
	if *debug {
		fmt.Printf("[downloadproxy] done\n")
	}
	return nil
}

func DownloadStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	return nil
}
