package srv

import (
	//	"context"
	"fmt"

	pb "golang.conradwood.net/apis/h2gproxy"

	//"golang.conradwood.net/go-easyops/utils"
	//	"google.golang.org/grpc"
	"io"
	"sync"

	"golang.conradwood.net/h2gproxy/grpchelpers"
	"golang.org/x/net/websocket"
)

func WebSocketProxy(f *FProxy) {
	wsi := &websock_instance{f: f, wg: &sync.WaitGroup{}}
	err := wsi.websocket_proxy_exe(f)
	if err != nil {
		f.Debugf("websocket proxy failed: %s\n", err)
	}
}

type websock_instance struct {
	f                         *FProxy
	stream                    grpchelpers.ClientStream
	stop_backend_frame_reader bool
	ws_handler                websocket.Handler
	wg                        *sync.WaitGroup
}

func (wsi *websock_instance) websocket_proxy_exe(f *FProxy) error {
	auth_result, err := json_auth(f) // always check if we got auth stuff
	if err != nil {
		return err
	}

	svc := grpchelpers.GetGRPCConnection(f.hf.def.TargetService)
	f.Debugf("service: %s\n", svc)
	ctx, cancel, err := createCancellableContext(f, auth_result)
	if err != nil {
		return err
	}
	defer svc.Close()
	defer cancel() // propagate browser close() to backend
	wsi.stream, err = svc.OpenStream(ctx, "WebSocketHTTP", true, true)
	if err != nil {
		return err
	}
	defer wsi.stream.Finish()
	f.Debugf("websocket proxy allocated new stream (%s)\n", wsi.stream)

	wsi.ws_handler = websocket.Handler(wsi.websocket_handler)
	wsi.wg.Add(1)
	wsi.debugf("Starting websocket handler\n")
	go wsi.ws_handler.ServeHTTP(f.writer, f.req)
	wsi.debugf("websocket handler finished\n")
	wsi.wg.Wait()
	wsi.stream.CloseSend()

	wsi.debugf("req/resp done\n")
	return nil
}

// copy frames from backend to browser
func (wsi *websock_instance) backend_to_browser(ws *websocket.Conn) error {
	wsi.debugf("Started frame_to_browser thread\n")
	msg := &pb.WebSocketResponse{}
	for wsi.stop_backend_frame_reader == false {
		err := wsi.stream.RecvMsg(msg)
		if err != nil {
			if err == io.EOF {
				break
			}
			wsi.debugf("frame_to_browser failed: %s\n", err)
			return err
		}
		if wsi.stop_backend_frame_reader {
			break
		}
		wsi.debugf("From backend: %#v\n", msg)
		_, err = ws.Write(msg.Frame)
		if err != nil {
			wsi.debugf("to browser: %s\n", err)
			break
		}
	}
	wsi.debugf("frame-to-browser finished\n")
	return nil
}

// handle the websocket proto
func (wsi *websock_instance) websocket_handler(ws *websocket.Conn) {
	wsi.debugf("handling websocket\n")
	go wsi.backend_to_browser(ws)
	buf := make([]byte, 8192)
	for {
		n, err := ws.Read(buf)
		if n > 0 {
			msg := &pb.WebSocketRequest{Frame: buf[:n]}
			serr := wsi.stream.SendMsg(msg)
			if serr != nil {
				if serr == io.EOF {
					break
				}
				wsi.debugf("Failed: %s\n", serr)
				break
			}
			wsi.debugf("Send %d bytes to backend\n", len(msg.Frame))
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			wsi.debugf("websock.read() failed: %s\n", err)
			break
		}

	}
	wsi.stop_backend_frame_reader = true
	wsi.debugf("websock handler finished\n")
	wsi.wg.Done()
}

func (wsi *websock_instance) debugf(format string, args ...interface{}) {
	fmt.Printf("[websocket] "+format, args...)
}
