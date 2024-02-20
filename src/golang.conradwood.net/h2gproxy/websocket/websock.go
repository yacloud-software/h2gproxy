package websocket

import (
	h2g "golang.conradwood.net/apis/h2gproxy"
	"io"
	// "golang.conradwood.net/go-easyops/utils"
	"context"
	"sync"
)

// read/write are safe to use from different threads
type WebSocketServer struct {
	srv     WsConn
	handler WebSocketHandler
	wlock   sync.Mutex
}

type WebSocketHandler interface {
	Receive(buf []byte) error
	ConClosed(error)
}

type WsConn interface {
	Context() context.Context
	Send(*h2g.WebSocketResponse) error
	Recv() (*h2g.WebSocketRequest, error)
}

func NewWebSocketServer(srv WsConn, handler WebSocketHandler) *WebSocketServer {
	ws := &WebSocketServer{srv: srv, handler: handler}
	go ws.receiver_loop()
	return ws
}
func (w *WebSocketServer) receiver_loop() {
	var res_err error
	for {
		r, r_err := w.srv.Recv()
		if r != nil {
			err := w.handler.Receive(r.Frame)
			if err != nil {
				if err == io.EOF {
					err = nil
					break
				}
				res_err = err
				break
			}
		}
		if r_err != nil {
			if r_err != io.EOF {
				res_err = r_err
				break
			}
		}
	}
	w.handler.ConClosed(res_err)
}
func (w *WebSocketServer) Write(frame []byte) (int, error) {
	w.wlock.Lock()
	defer w.wlock.Unlock()
	wr := &h2g.WebSocketResponse{Frame: frame}
	err := w.srv.Send(wr)
	if err != nil {
		return 0, err
	}
	return len(frame), nil
}
