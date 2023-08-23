package srv

import (
	"fmt"
	//	"golang.conradwood.net/apis/create"
	"golang.conradwood.net/apis/h2gproxy"
	//	hm "golang.conradwood.net/apis/htmlserver"
	"golang.conradwood.net/go-easyops/client"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"sync"
)

var (
	//	html  hm.HTMLServerServiceClient
	htmls    = make(map[string]Ihtmlserve)
	htmllock sync.Mutex
)

/*****************************
* web
*****************************/

type web_proxy struct {
	f *FProxy
}

func WebProxy(f *FProxy) {
	wp := &web_proxy{f: f}
	gp := NewGrpcProxy(f, wp)
	gp.Proxy()
}

func (j *web_proxy) Serve(ctx context.Context, in *h2gproxy.ServeRequest) (*h2gproxy.ServeResponse, error) {
	t := j.f.hf.def.TargetService
	if t == "" {
		fmt.Printf("foo: %#v\n", j.f.hf.def.TargetService)
		fmt.Printf("foo: %#v\n", j.f.hf.def)
		t = "htmlserver.HTMLServerService"
	}

	//	fmt.Printf("foo: %#v\n", j.f.hf.def.TargetService)
	html := getservice(t)
	return j.f.with_session_cookie(html.ServeHTML(ctx, in))
}

type Ihtmlserve interface {
	ServeHTML(ctx context.Context, in *h2gproxy.ServeRequest, opts ...grpc.CallOption) (*h2gproxy.ServeResponse, error)
}

type htmlserve struct {
	name string
	cc   *grpc.ClientConn
}

func (h *htmlserve) ServeHTML(ctx context.Context, in *h2gproxy.ServeRequest, opts ...grpc.CallOption) (*h2gproxy.ServeResponse, error) {
	out := new(h2gproxy.ServeResponse)
	p := fmt.Sprintf("/%s/ServeHTML", h.name)
	err := grpc.Invoke(ctx, p, in, out, h.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func getservice(name string) Ihtmlserve {
	if name == "" {
		panic("no name")

	}
	res := htmls[name]
	if res != nil {
		return res
	}
	htmllock.Lock()
	defer htmllock.Unlock()
	res = htmls[name]
	if res != nil {
		return res
	}
	hs := &htmlserve{cc: client.Connect(name), name: name}
	htmls[name] = hs
	return hs
}
